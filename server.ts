import 'dotenv/config';
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import multer from 'multer';
import { createServer as createViteServer } from 'vite';
import { db, generateId, initSchema, uploadsDir } from './server/db.ts';
import { ensureSeedUpgrades, ensureStudentStarterData, seedDemonstrationData } from './server/seed.ts';
import {
  type AuthenticatedRequest,
  createSessionToken,
  hashPassword,
  mapDbUserToProfile,
  requireAuth,
  requireRole,
  SESSION_COOKIE_NAME,
  verifyPassword,
} from './server/auth.ts';
import {
  calculateCreditWeightedCgpa,
  evaluatePlacementEligibility,
} from './src/shared/eligibility.ts';
import { generateCampusAssistantReply, streamCampusAssistantReply } from './server/ai.ts';
import type { ApplicationStatus, CalendarItem } from './src/shared/types.ts';

initSchema();
seedDemonstrationData();
ensureSeedUpgrades();

const app = express();
app.use(express.json({ limit: '5mb' }));

// File Upload Configuration
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadsDir),
  filename: (_req, file, cb) => {
    const safeName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, `${Date.now()}_${Math.random().toString(36).slice(2, 7)}_${safeName}`);
  },
});

const resumeUpload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const isPdf = file.mimetype === 'application/pdf' || file.originalname.toLowerCase().endsWith('.pdf');
    if (!isPdf) {
      return cb(new Error('Only PDF resumes (.pdf) are allowed.'));
    }
    cb(null, true);
  },
});

const docUpload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
});

function setSessionCookie(req: express.Request, res: express.Response, userId: string): string {
  const token = createSessionToken(userId);
  const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https';
  res.cookie(SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: isHttps ? 'none' : 'lax',
    secure: isHttps,
    path: '/',
    maxAge: 1000 * 60 * 60 * 24 * 7,
  });
  return token;
}

function createNotification(
  userId: string,
  title: string,
  message: string,
  type: string,
  linkModule: string
) {
  db.prepare(
    'INSERT INTO notifications (id, userId, title, message, type, linkModule, isRead, createdAt) VALUES (?, ?, ?, ?, ?, ?, 0, ?)'
  ).run(generateId('notif'), userId, title, message, type, linkModule, new Date().toISOString());
}

function dispatchConfirmationEmail(params: {
  userId: string;
  recipientEmail: string;
  fullName: string;
  role: string;
  universityId: string;
  kind: 'registration' | 'signin';
}) {
  const confirmationCode = `CONF-${Math.floor(100000 + Math.random() * 899999)}`;
  const now = new Date().toISOString();
  const isFaculty = params.role === 'faculty';
  const subject =
    params.kind === 'registration'
      ? `CampusCopilot ${isFaculty ? 'Faculty' : 'Student'} Account Confirmation (${confirmationCode})`
      : `CampusCopilot ${isFaculty ? 'Faculty' : 'Account'} Sign-In Confirmation (${confirmationCode})`;
  const bodyText =
    params.kind === 'registration'
      ? `Hello ${params.fullName}, your ${params.role} account (${params.universityId}) for ${params.recipientEmail} has been confirmed and activated on CampusCopilot. Reference Code: ${confirmationCode}.`
      : `Hello ${params.fullName}, a sign-in to your ${params.role} account (${params.recipientEmail}) was confirmed at ${now}. Reference Code: ${confirmationCode}.`;

  const id = generateId('mail');
  const status = process.env.SMTP_HOST ? 'Sent via SMTP' : 'Dispatched (University Mail Outbox)';
  db.prepare(`
    INSERT INTO email_confirmations (id, userId, recipientEmail, role, confirmationCode, subject, bodyText, status, createdAt)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, params.userId, params.recipientEmail, params.role, confirmationCode, subject, bodyText, status, now);

  return db.prepare('SELECT * FROM email_confirmations WHERE id = ?').get(id) as any;
}

// ==================== HEALTH & SYSTEM STATUS ====================
app.get('/api/system/status', (_req, res) => {
  const firebaseConfigured = fs.existsSync(path.resolve(process.cwd(), 'firebase-applet-config.json'));
  const geminiConfigured = Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY');
  res.json({
    databaseEngine: 'SQLite (Persistent Server Storage)',
    firebaseConfigured,
    geminiConfigured,
    uploadsDirectory: 'uploads/',
  });
});

// ==================== AUTHENTICATION ====================
app.get('/api/auth/me', requireAuth, (req: AuthenticatedRequest, res) => {
  res.json({ user: req.user });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'University email (or ID) and password are required.' });
  }
  const identifier = String(email).trim();
  const row = db
    .prepare('SELECT * FROM users WHERE lower(email) = lower(?) OR lower(universityId) = lower(?)')
    .get(identifier, identifier) as any;
  if (!row || !verifyPassword(String(password), row.passwordHash)) {
    return res.status(401).json({ error: 'Invalid university email or password.' });
  }
  const token = setSessionCookie(req, res, row.id);

  let confirmation: any = null;
  if (row.role === 'faculty') {
    confirmation = dispatchConfirmationEmail({
      userId: row.id,
      recipientEmail: row.email,
      fullName: row.fullName,
      role: row.role,
      universityId: row.facultyId || row.universityId,
      kind: 'signin',
    });
    createNotification(
      row.id,
      'Faculty Sign-In Confirmation Email Dispatched',
      `Confirmation notice (${confirmation.confirmationCode}) sent to ${row.email}. View details in Notifications or Profile.`,
      'announcement',
      'profile'
    );
  }

  res.json({ user: mapDbUserToProfile(row), token, confirmation });
});

app.post('/api/auth/register', (req, res) => {
  const body = req.body || {};
  const {
    fullName,
    email,
    password,
    confirmPassword,
    departmentId,
    role,
    universityId,
    rollNumber,
    branch,
    academicYear,
    semester,
    section,
    graduationYear,
    cgpa,
    phone,
    facultyId,
    designation,
    assignedSubjects,
    assignedClasses,
  } = body;

  if (!fullName || !email || !password || !departmentId || !role) {
    return res.status(400).json({ error: 'Please complete all required common registration fields.' });
  }

  // Strictly block coordinator & admin self-registration
  if (role !== 'student' && role !== 'faculty') {
    return res.status(403).json({
      error:
        'Placement Coordinator and Administrator accounts require authorized administrative assignment and cannot be created via public signup.',
    });
  }

  if (String(password).length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
  }
  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Password and confirm password do not match.' });
  }

  const dept = db.prepare('SELECT * FROM departments WHERE id = ? OR code = ?').get(departmentId, departmentId) as any;
  if (!dept) {
    return res.status(400).json({ error: 'Selected department does not exist.' });
  }

  const normalizedEmail = String(email).trim().toLowerCase();
  const existingUser = db
    .prepare('SELECT * FROM users WHERE lower(email) = lower(?)')
    .get(normalizedEmail) as any;
  if (existingUser) {
    if (verifyPassword(String(password), existingUser.passwordHash)) {
      const token = setSessionCookie(req, res, existingUser.id);
      let confirmation: any = null;
      if (existingUser.role === 'faculty') {
        confirmation = dispatchConfirmationEmail({
          userId: existingUser.id,
          recipientEmail: existingUser.email,
          fullName: existingUser.fullName,
          role: existingUser.role,
          universityId: existingUser.facultyId || existingUser.universityId,
          kind: 'signin',
        });
      }
      return res.status(200).json({
        user: mapDbUserToProfile(existingUser),
        token,
        confirmation,
        existingAccountLoggedIn: true,
      });
    }
    return res.status(409).json({
      error: 'An account with this university email already exists. Click Login below to sign in with your password.',
      code: 'EMAIL_EXISTS',
    });
  }

  const baseUid =
    universityId && String(universityId).trim()
      ? String(universityId).trim()
      : `${role === 'student' ? 'UNI' : 'FAC'}-2026-${Math.floor(1000 + Math.random() * 8999)}`;

  let resolvedUniversityId = baseUid;
  let suffix = 2;
  while (db.prepare('SELECT id FROM users WHERE lower(universityId) = lower(?)').get(resolvedUniversityId)) {
    resolvedUniversityId = `${baseUid}-${suffix}`;
    suffix += 1;
  }

  const resolvedFacultyId =
    role === 'faculty'
      ? (facultyId && String(facultyId).trim() ? String(facultyId).trim() : resolvedUniversityId)
      : null;

  if (role === 'student') {
    if (!rollNumber || !branch || !academicYear || !semester || !section || !graduationYear || !phone) {
      return res.status(400).json({ error: 'Please complete all required student academic and contact fields.' });
    }
  } else if (role === 'faculty') {
    if (!designation) {
      return res.status(400).json({ error: 'Please provide your Faculty Designation.' });
    }
  }

  const id = generateId(role === 'student' ? 'usr_stu' : 'usr_fac');
  const now = new Date().toISOString();
  const parsedCgpa = cgpa !== undefined && cgpa !== '' && cgpa !== null ? Number(cgpa) : null;

  db.prepare(`
    INSERT INTO users (
      id, fullName, email, passwordHash, role, universityId, departmentId, departmentName,
      rollNumber, branch, academicYear, semester, section, graduationYear, cgpa, backlogs, phone,
      skillsJson, projects, facultyId, designation, assignedSubjectsJson, assignedClassesJson, createdAt, updatedAt
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    String(fullName).trim(),
    normalizedEmail,
    hashPassword(String(password)),
    role,
    resolvedUniversityId,
    dept.id,
    dept.name,
    role === 'student' ? String(rollNumber).trim() : null,
    role === 'student' ? String(branch).trim() : null,
    role === 'student' ? String(academicYear).trim() : null,
    role === 'student' ? Number(semester) : null,
    role === 'student' ? String(section).trim().toUpperCase() : null,
    role === 'student' ? Number(graduationYear) : null,
    role === 'student' && parsedCgpa !== null && !Number.isNaN(parsedCgpa) ? parsedCgpa : null,
    0,
    phone ? String(phone).trim() : null,
    '[]',
    '',
    resolvedFacultyId,
    role === 'faculty' ? String(designation).trim() : null,
    JSON.stringify(Array.isArray(assignedSubjects) ? assignedSubjects : []),
    JSON.stringify(Array.isArray(assignedClasses) ? assignedClasses : []),
    now,
    now
  );

  const confirmation = dispatchConfirmationEmail({
    userId: id,
    recipientEmail: normalizedEmail,
    fullName: String(fullName).trim(),
    role,
    universityId: resolvedUniversityId,
    kind: 'registration',
  });

  if (role === 'student') {
    ensureStudentStarterData(id);
  }

  createNotification(
    id,
    'Welcome to CampusCopilot · Account Confirmation Sent',
    role === 'student'
      ? `Confirmation (${confirmation.confirmationCode}) dispatched to ${normalizedEmail}. Your academic transcript, attendance baseline, timetable, and deadline alerts are ready.`
      : `Faculty confirmation email (${confirmation.confirmationCode}) dispatched to ${normalizedEmail}. Your faculty workspace is active.`,
    'announcement',
    'profile'
  );

  const created = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  const token = setSessionCookie(req, res, id);
  res.status(201).json({ user: mapDbUserToProfile(created), token, confirmation });
});

app.get('/api/auth/confirmations', requireAuth, (req: AuthenticatedRequest, res) => {
  const rows = db
    .prepare('SELECT * FROM email_confirmations WHERE userId = ? ORDER BY createdAt DESC LIMIT 20')
    .all(req.user!.id);
  res.json({ confirmations: rows });
});

app.post('/api/auth/resend-confirmation', requireAuth, (req: AuthenticatedRequest, res) => {
  const user = req.user!;
  const confirmation = dispatchConfirmationEmail({
    userId: user.id,
    recipientEmail: user.email,
    fullName: user.fullName,
    role: user.role,
    universityId: user.facultyId || user.universityId,
    kind: 'registration',
  });
  createNotification(
    user.id,
    'Confirmation Email Re-Dispatched',
    `A new confirmation mail (${confirmation.confirmationCode}) was sent to ${user.email}.`,
    'announcement',
    'profile'
  );
  res.status(201).json({ confirmation });
});

app.post('/api/auth/logout', (req, res) => {
  const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https';
  res.clearCookie(SESSION_COOKIE_NAME, {
    path: '/',
    sameSite: isHttps ? 'none' : 'lax',
    secure: isHttps,
  });
  res.json({ ok: true });
});

app.post('/api/auth/reset-password', (req, res) => {
  const { email, universityId, newPassword } = req.body || {};
  if (!email || !universityId || !newPassword) {
    return res.status(400).json({ error: 'University email, University ID, and new password are required.' });
  }
  if (String(newPassword).length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters.' });
  }
  const user = db
    .prepare('SELECT id FROM users WHERE lower(email) = lower(?) AND lower(universityId) = lower(?)')
    .get(String(email).trim(), String(universityId).trim()) as any;
  if (!user) {
    return res.status(404).json({ error: 'No matching account found for that email and University ID.' });
  }
  db.prepare('UPDATE users SET passwordHash = ?, updatedAt = ? WHERE id = ?').run(
    hashPassword(String(newPassword)),
    new Date().toISOString(),
    user.id
  );
  res.json({ message: 'Password updated successfully. You may now sign in.' });
});

app.put('/api/profile', requireAuth, (req: AuthenticatedRequest, res) => {
  const user = req.user!;
  const { fullName, phone, skills, projects, designation, section, semester } = req.body || {};
  const now = new Date().toISOString();

  db.prepare(`
    UPDATE users SET
      fullName = COALESCE(?, fullName),
      phone = COALESCE(?, phone),
      skillsJson = COALESCE(?, skillsJson),
      projects = COALESCE(?, projects),
      designation = COALESCE(?, designation),
      section = COALESCE(?, section),
      semester = COALESCE(?, semester),
      updatedAt = ?
    WHERE id = ?
  `).run(
    fullName ? String(fullName).trim() : null,
    phone !== undefined ? String(phone).trim() : null,
    Array.isArray(skills) ? JSON.stringify(skills) : null,
    projects !== undefined ? String(projects) : null,
    designation !== undefined ? String(designation) : null,
    section !== undefined ? String(section).toUpperCase() : null,
    semester !== undefined ? Number(semester) : null,
    now,
    user.id
  );

  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
  res.json({ user: mapDbUserToProfile(updated) });
});

// Public metadata for signup dropdowns
app.get('/api/departments', (_req, res) => {
  const rows = db.prepare('SELECT * FROM departments ORDER BY name ASC').all();
  res.json({ departments: rows });
});

app.get('/api/subjects', requireAuth, (req: AuthenticatedRequest, res) => {
  const { departmentId, semester } = req.query;
  let query = 'SELECT * FROM subjects WHERE 1=1';
  const params: any[] = [];
  if (departmentId) {
    query += ' AND departmentId = ?';
    params.push(departmentId);
  }
  if (semester) {
    query += ' AND semester = ?';
    params.push(Number(semester));
  }
  query += ' ORDER BY code ASC';
  const subjects = db.prepare(query).all(...params);
  res.json({ subjects });
});

// ==================== ACADEMIC RECORDS & CGPA ====================
app.get('/api/academic-records', requireAuth, (req: AuthenticatedRequest, res) => {
  const user = req.user!;
  const targetStudentId =
    req.query.studentId && (user.role === 'faculty' || user.role === 'admin' || user.role === 'coordinator')
      ? String(req.query.studentId)
      : user.id;

  const rows = db
    .prepare('SELECT * FROM academic_records WHERE studentId = ? ORDER BY semester ASC')
    .all(targetStudentId)
    .map((r: any) => ({
      ...r,
      subjects: JSON.parse(r.subjectsJson || '[]'),
    }));

  const cgpa = calculateCreditWeightedCgpa(rows);
  res.json({ records: rows, verifiedCgpa: cgpa });
});

app.post(
  '/api/academic-records',
  requireAuth,
  requireRole('faculty', 'admin'),
  (req: AuthenticatedRequest, res) => {
    const { studentId, semester, subjects } = req.body || {};
    if (!studentId || !semester || !Array.isArray(subjects) || subjects.length === 0) {
      return res.status(400).json({ error: 'Student ID, semester, and at least one subject grade are required.' });
    }
    const student = db.prepare('SELECT * FROM users WHERE id = ? AND role = ?').get(studentId, 'student') as any;
    if (!student) {
      return res.status(404).json({ error: 'Student record not found.' });
    }

    let totalWeighted = 0;
    let totalCredits = 0;
    for (const s of subjects) {
      const credits = Number(s.credits);
      const gp = Number(s.gradePoints);
      if (!s.subjectCode || !s.subjectName || Number.isNaN(credits) || credits <= 0 || Number.isNaN(gp) || gp < 0 || gp > 10) {
        return res.status(400).json({ error: 'Each subject must include code, name, valid credits (>0), and gradePoints (0-10).' });
      }
      totalWeighted += credits * gp;
      totalCredits += credits;
    }
    const sgpa = Number((totalWeighted / totalCredits).toFixed(2));
    const now = new Date().toISOString();

    const existing = db
      .prepare('SELECT id FROM academic_records WHERE studentId = ? AND semester = ?')
      .get(studentId, Number(semester)) as any;

    if (existing) {
      db.prepare(`
        UPDATE academic_records SET sgpa = ?, totalCredits = ?, subjectsJson = ?, verifiedBy = ?, verifiedAt = ?, updatedAt = ?
        WHERE id = ?
      `).run(sgpa, totalCredits, JSON.stringify(subjects), req.user!.fullName, now, now, existing.id);
    } else {
      db.prepare(`
        INSERT INTO academic_records (id, studentId, semester, sgpa, totalCredits, subjectsJson, verifiedBy, verifiedAt, updatedAt)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(generateId('acad'), studentId, Number(semester), sgpa, totalCredits, JSON.stringify(subjects), req.user!.fullName, now, now);
    }

    const allRecs = db
      .prepare('SELECT * FROM academic_records WHERE studentId = ? ORDER BY semester ASC')
      .all(studentId)
      .map((r: any) => ({ ...r, subjects: JSON.parse(r.subjectsJson || '[]') }));
    const newCgpa = calculateCreditWeightedCgpa(allRecs);
    if (newCgpa !== null) {
      db.prepare('UPDATE users SET cgpa = ?, updatedAt = ? WHERE id = ?').run(newCgpa, now, studentId);
    }

    createNotification(
      studentId,
      `Semester ${semester} Academic Record Published`,
      `Your Semester ${semester} grades (SGPA: ${sgpa.toFixed(2)}) have been verified by ${req.user!.fullName}.`,
      'announcement',
      'academics'
    );

    res.status(201).json({ records: allRecs, verifiedCgpa: newCgpa });
  }
);

// ==================== ATTENDANCE MANAGEMENT ====================
app.get('/api/attendance/summary', requireAuth, (req: AuthenticatedRequest, res) => {
  const user = req.user!;
  const targetStudentId =
    req.query.studentId && (user.role === 'faculty' || user.role === 'admin')
      ? String(req.query.studentId)
      : user.id;

  const records = db
    .prepare('SELECT * FROM attendance_records WHERE studentId = ? ORDER BY sessionDate DESC, updatedAt DESC')
    .all(targetStudentId) as any[];

  const bySubject: Record<
    string,
    { subjectId: string; subjectCode: string; subjectName: string; presentClasses: number; absentClasses: number; totalConducted: number }
  > = {};
  const byMonth: Record<string, { present: number; total: number }> = {};

  let overallPresent = 0;
  let overallAbsent = 0;

  for (const r of records) {
    if (!bySubject[r.subjectId]) {
      bySubject[r.subjectId] = {
        subjectId: r.subjectId,
        subjectCode: r.subjectCode,
        subjectName: r.subjectName,
        presentClasses: 0,
        absentClasses: 0,
        totalConducted: 0,
      };
    }
    bySubject[r.subjectId].totalConducted += 1;
    const monthKey = String(r.sessionDate).slice(0, 7);
    if (!byMonth[monthKey]) byMonth[monthKey] = { present: 0, total: 0 };
    byMonth[monthKey].total += 1;

    if (r.status === 'present') {
      bySubject[r.subjectId].presentClasses += 1;
      byMonth[monthKey].present += 1;
      overallPresent += 1;
    } else {
      bySubject[r.subjectId].absentClasses += 1;
      overallAbsent += 1;
    }
  }

  const overallTotal = overallPresent + overallAbsent;
  const overallPercentage = overallTotal > 0 ? Number(((overallPresent / overallTotal) * 100).toFixed(2)) : 0;

  const subjects = Object.values(bySubject).map((s) => ({
    ...s,
    percentage: s.totalConducted > 0 ? Number(((s.presentClasses / s.totalConducted) * 100).toFixed(2)) : 0,
  }));

  const monthly = Object.entries(byMonth)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([month, m]) => ({
      month,
      present: m.present,
      total: m.total,
      percentage: m.total > 0 ? Number(((m.present / m.total) * 100).toFixed(2)) : 0,
    }));

  res.json({
    summary: {
      overallPresent,
      overallAbsent,
      overallTotal,
      overallPercentage,
      subjects,
      monthly,
      history: records,
    },
  });
});

app.get(
  '/api/attendance/faculty/roster',
  requireAuth,
  requireRole('faculty', 'admin'),
  (req: AuthenticatedRequest, res) => {
    const { subjectId, semester, section, sessionDate } = req.query;
    if (!subjectId || !semester || !section || !sessionDate) {
      return res.status(400).json({ error: 'subjectId, semester, section, and sessionDate are required.' });
    }
    const subject = db.prepare('SELECT * FROM subjects WHERE id = ?').get(String(subjectId)) as any;
    if (!subject) {
      return res.status(404).json({ error: 'Subject not found.' });
    }
    const students = db
      .prepare(
        `SELECT id, fullName, rollNumber, branch, semester, section, email
         FROM users
         WHERE role = 'student' AND departmentId = ? AND semester = ? AND section = ?
         ORDER BY rollNumber ASC`
      )
      .all(subject.departmentId, Number(semester), String(section).toUpperCase()) as any[];

    const existingSession = db
      .prepare('SELECT * FROM attendance_sessions WHERE subjectId = ? AND semester = ? AND section = ? AND sessionDate = ?')
      .get(String(subjectId), Number(semester), String(section).toUpperCase(), String(sessionDate)) as any;

    let existingMarks: Record<string, 'present' | 'absent'> = {};
    if (existingSession) {
      const rows = db
        .prepare('SELECT studentId, status FROM attendance_records WHERE sessionId = ?')
        .all(existingSession.id) as any[];
      for (const r of rows) {
        existingMarks[r.studentId] = r.status;
      }
    }

    res.json({
      subject,
      existingSession: existingSession || null,
      students: students.map((s) => ({
        ...s,
        existingStatus: existingMarks[s.id] || null,
      })),
    });
  }
);

app.post(
  '/api/attendance/faculty/mark',
  requireAuth,
  requireRole('faculty', 'admin'),
  (req: AuthenticatedRequest, res) => {
    const { subjectId, semester, section, sessionDate, topic, entries, allowCorrection } = req.body || {};
    if (!subjectId || !semester || !section || !sessionDate || !Array.isArray(entries) || entries.length === 0) {
      return res.status(400).json({ error: 'Subject, semester, section, date, and student attendance entries are required.' });
    }
    const subject = db.prepare('SELECT * FROM subjects WHERE id = ?').get(String(subjectId)) as any;
    if (!subject) {
      return res.status(404).json({ error: 'Subject not found.' });
    }

    // Faculty authorization check (faculty can manage subjects in their department or assigned to them)
    if (
      req.user!.role === 'faculty' &&
      subject.departmentId !== req.user!.departmentId &&
      subject.facultyId !== req.user!.id
    ) {
      return res.status(403).json({ error: 'You are not authorized to mark attendance for this department/subject.' });
    }

    const normalizedSection = String(section).toUpperCase();
    const existingSession = db
      .prepare('SELECT * FROM attendance_sessions WHERE subjectId = ? AND semester = ? AND section = ? AND sessionDate = ?')
      .get(subject.id, Number(semester), normalizedSection, String(sessionDate)) as any;

    if (existingSession && !allowCorrection) {
      return res.status(409).json({
        error: `Duplicate attendance prevented: Attendance for ${subject.code} (Sem ${semester} Sec ${normalizedSection}) on ${sessionDate} is already recorded. Enable correction mode to update an existing session.`,
      });
    }

    const now = new Date().toISOString();
    const saveTx = db.transaction(() => {
      let sessionId = existingSession?.id;
      if (!sessionId) {
        sessionId = generateId('sess');
        db.prepare(`
          INSERT INTO attendance_sessions (id, subjectId, subjectCode, subjectName, facultyId, facultyName, department, semester, section, sessionDate, topic, createdAt)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          sessionId,
          subject.id,
          subject.code,
          subject.name,
          req.user!.id,
          req.user!.fullName,
          subject.departmentName,
          Number(semester),
          normalizedSection,
          String(sessionDate),
          String(topic || '').trim(),
          now
        );
      } else if (topic !== undefined) {
        db.prepare('UPDATE attendance_sessions SET topic = ? WHERE id = ?').run(String(topic).trim(), sessionId);
      }

      const upsertRec = db.prepare(`
        INSERT INTO attendance_records (id, sessionId, studentId, subjectId, subjectCode, subjectName, sessionDate, status, markedBy, updatedAt)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(sessionId, studentId) DO UPDATE SET status = excluded.status, markedBy = excluded.markedBy, updatedAt = excluded.updatedAt
      `);

      for (const entry of entries) {
        if (entry.status !== 'present' && entry.status !== 'absent') {
          throw new Error('Invalid attendance status. Must be present or absent.');
        }
        upsertRec.run(
          generateId('att'),
          sessionId,
          entry.studentId,
          subject.id,
          subject.code,
          subject.name,
          String(sessionDate),
          entry.status,
          req.user!.fullName,
          now
        );
      }
      return sessionId;
    });

    try {
      const sessionId = saveTx();
      res.status(existingSession ? 200 : 201).json({
        sessionId,
        corrected: Boolean(existingSession),
        message: existingSession
          ? `Updated attendance session for ${subject.code} on ${sessionDate}.`
          : `Saved new attendance session for ${subject.code} on ${sessionDate}.`,
      });
    } catch (err: any) {
      res.status(400).json({ error: err.message || 'Failed to save attendance.' });
    }
  }
);

app.get(
  '/api/attendance/faculty/reports',
  requireAuth,
  requireRole('faculty', 'admin'),
  (req: AuthenticatedRequest, res) => {
    const user = req.user!;
    const sessions = db
      .prepare(
        user.role === 'admin'
          ? `SELECT s.*,
              SUM(CASE WHEN r.status = 'present' THEN 1 ELSE 0 END) as presentCount,
              COUNT(r.id) as totalStudents
             FROM attendance_sessions s
             LEFT JOIN attendance_records r ON r.sessionId = s.id
             GROUP BY s.id
             ORDER BY s.sessionDate DESC LIMIT 40`
          : `SELECT s.*,
              SUM(CASE WHEN r.status = 'present' THEN 1 ELSE 0 END) as presentCount,
              COUNT(r.id) as totalStudents
             FROM attendance_sessions s
             LEFT JOIN attendance_records r ON r.sessionId = s.id
             WHERE s.department = ?
             GROUP BY s.id
             ORDER BY s.sessionDate DESC LIMIT 40`
      )
      .all(...(user.role === 'admin' ? [] : [user.departmentName]));

    const studentReport = db
      .prepare(
        user.role === 'admin'
          ? `SELECT u.id as studentId, u.fullName, u.rollNumber, u.departmentName, u.semester, u.section,
              SUM(CASE WHEN r.status = 'present' THEN 1 ELSE 0 END) as presentCount,
              COUNT(r.id) as totalCount
             FROM users u
             LEFT JOIN attendance_records r ON r.studentId = u.id
             WHERE u.role = 'student'
             GROUP BY u.id
             ORDER BY u.rollNumber ASC`
          : `SELECT u.id as studentId, u.fullName, u.rollNumber, u.departmentName, u.semester, u.section,
              SUM(CASE WHEN r.status = 'present' THEN 1 ELSE 0 END) as presentCount,
              COUNT(r.id) as totalCount
             FROM users u
             LEFT JOIN attendance_records r ON r.studentId = u.id
             WHERE u.role = 'student' AND u.departmentId = ?
             GROUP BY u.id
             ORDER BY u.rollNumber ASC`
      )
      .all(...(user.role === 'admin' ? [] : [user.departmentId]));

    res.json({ sessions, studentReport });
  }
);

// ==================== TIMETABLES ====================
app.get('/api/timetables', requireAuth, (req: AuthenticatedRequest, res) => {
  const user = req.user!;
  if (user.role === 'student') {
    let rows = db
      .prepare('SELECT * FROM timetables WHERE department = ? AND semester = ? AND section = ? ORDER BY startTime ASC')
      .all(user.departmentName, user.semester || 6, user.section || 'A');
    if (rows.length === 0) {
      rows = db
        .prepare('SELECT * FROM timetables WHERE department = ? ORDER BY startTime ASC')
        .all(user.departmentName);
    }
    if (rows.length === 0) {
      rows = db
        .prepare("SELECT * FROM timetables WHERE department = 'Computer Science and Engineering' AND semester = 6 AND section = 'A' ORDER BY startTime ASC")
        .all();
    }
    return res.json({ timetable: rows });
  }
  if (user.role === 'faculty' && req.query.scope !== 'all') {
    const rows = db
      .prepare('SELECT * FROM timetables WHERE facultyId = ? ORDER BY startTime ASC')
      .all(user.id);
    return res.json({ timetable: rows });
  }
  const { department, semester, section } = req.query;
  let query = 'SELECT * FROM timetables WHERE 1=1';
  const params: any[] = [];
  if (department && department !== 'ALL') {
    query += ' AND department = ?';
    params.push(department);
  }
  if (semester && semester !== 'ALL') {
    query += ' AND semester = ?';
    params.push(Number(semester));
  }
  if (section && section !== 'ALL') {
    query += ' AND section = ?';
    params.push(String(section).toUpperCase());
  }
  query += ' ORDER BY startTime ASC';
  res.json({ timetable: db.prepare(query).all(...params) });
});

app.post('/api/timetables', requireAuth, requireRole('faculty', 'admin'), (req: AuthenticatedRequest, res) => {
  const { department, semester, section, dayOfWeek, startTime, endTime, subjectId, room, sessionType } = req.body || {};
  if (!department || !semester || !section || !dayOfWeek || !startTime || !endTime || !subjectId || !room) {
    return res.status(400).json({ error: 'All timetable slot fields are required.' });
  }
  const subject = db.prepare('SELECT * FROM subjects WHERE id = ?').get(subjectId) as any;
  if (!subject) return res.status(404).json({ error: 'Subject not found.' });

  const allowedTypes = ['Theory', 'Lab', 'Lecture', 'Project', 'Activity', 'Seminar'];
  const resolvedType = allowedTypes.includes(sessionType) ? sessionType : 'Lecture';

  const id = generateId('tt');
  db.prepare(`
    INSERT INTO timetables (id, department, semester, section, dayOfWeek, startTime, endTime, subjectId, subjectCode, subjectName, facultyId, facultyName, room, sessionType)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    department,
    Number(semester),
    String(section).toUpperCase(),
    dayOfWeek,
    startTime,
    endTime,
    subject.id,
    subject.code,
    subject.name,
    subject.facultyId || req.user!.id,
    subject.facultyName || req.user!.fullName,
    room,
    resolvedType
  );
  res.status(201).json({ id });
});

app.delete('/api/timetables/:id', requireAuth, requireRole('faculty', 'admin'), (req, res) => {
  db.prepare('DELETE FROM timetables WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ==================== ASSIGNMENTS & SUBMISSIONS ====================
app.get('/api/assignments', requireAuth, (req: AuthenticatedRequest, res) => {
  const user = req.user!;
  if (user.role === 'student') {
    const rows = db
      .prepare(
        `SELECT * FROM assignments
         WHERE (department = ? OR department = 'ALL')
           AND (semester = ? OR semester = 0)
           AND (section = ? OR section = 'ALL')
         ORDER BY deadline ASC`
      )
      .all(user.departmentName, user.semester || 6, user.section || 'A') as any[];
    const enriched = rows.map((a) => {
      const sub = db
        .prepare('SELECT * FROM submissions WHERE assignmentId = ? AND studentId = ?')
        .get(a.id, user.id) as any;
      return {
        ...a,
        attachmentUrl: a.attachmentPath ? `/api/files/${encodeURIComponent(a.attachmentPath)}` : null,
        mySubmission: sub
          ? { ...sub, fileUrl: sub.filePath ? `/api/files/${encodeURIComponent(sub.filePath)}` : null }
          : null,
      };
    });
    return res.json({ assignments: enriched });
  }

  const rows = db
    .prepare(
      user.role === 'faculty'
        ? 'SELECT * FROM assignments WHERE facultyId = ? OR department = ? ORDER BY deadline ASC'
        : 'SELECT * FROM assignments ORDER BY deadline ASC'
    )
    .all(...(user.role === 'faculty' ? [user.id, user.departmentName] : [])) as any[];

  const enriched = rows.map((a) => {
    const countRow = db.prepare('SELECT COUNT(*) as c FROM submissions WHERE assignmentId = ?').get(a.id) as any;
    return {
      ...a,
      attachmentUrl: a.attachmentPath ? `/api/files/${encodeURIComponent(a.attachmentPath)}` : null,
      submissionCount: countRow.c,
    };
  });
  res.json({ assignments: enriched });
});

app.post('/api/assignments', requireAuth, requireRole('faculty', 'admin'), (req: AuthenticatedRequest, res) => {
  const { title, description, subjectId, semester, section, deadline, maxMarks, attachmentName, attachmentPath } = req.body || {};
  if (!title || !description || !subjectId || !semester || !section || !deadline) {
    return res.status(400).json({ error: 'Title, description, subject, semester, section, and deadline are required.' });
  }
  const subject = db.prepare('SELECT * FROM subjects WHERE id = ?').get(subjectId) as any;
  if (!subject) return res.status(404).json({ error: 'Subject not found.' });

  const id = generateId('asg');
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO assignments (id, title, description, subjectId, subjectCode, subjectName, department, semester, section, deadline, maxMarks, attachmentName, attachmentPath, facultyId, facultyName, createdAt)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    String(title).trim(),
    String(description).trim(),
    subject.id,
    subject.code,
    subject.name,
    subject.departmentName,
    Number(semester),
    String(section).toUpperCase(),
    deadline,
    Number(maxMarks) || 20,
    attachmentName || null,
    attachmentPath || null,
    req.user!.id,
    req.user!.fullName,
    now
  );

  // Notify matching students with exact submission date & time
  const students = db
    .prepare('SELECT id FROM users WHERE role = ? AND departmentName = ? AND semester = ? AND section = ?')
    .all('student', subject.departmentName, Number(semester), String(section).toUpperCase()) as any[];
  for (const s of students) {
    createNotification(
      s.id,
      `Submission Due: ${subject.code} · ${title}`,
      `Assignment submission deadline: ${String(deadline).replace('T', ' at ').slice(0, 19)}.`,
      'assignment',
      'assignments'
    );
  }

  res.status(201).json({ id });
});

app.post('/api/assignments/:id/submit', requireAuth, requireRole('student'), (req: AuthenticatedRequest, res) => {
  const user = req.user!;
  const assignment = db.prepare('SELECT * FROM assignments WHERE id = ?').get(req.params.id) as any;
  if (!assignment) return res.status(404).json({ error: 'Assignment not found.' });

  if (new Date(assignment.deadline).getTime() < Date.now()) {
    return res.status(400).json({ error: 'The submission deadline for this assignment has passed.' });
  }

  const { notes, fileName, filePath } = req.body || {};
  if (!notes && !filePath) {
    return res.status(400).json({ error: 'Please include submission notes or upload a submission document.' });
  }

  const now = new Date().toISOString();
  const existing = db
    .prepare('SELECT * FROM submissions WHERE assignmentId = ? AND studentId = ?')
    .get(assignment.id, user.id) as any;

  if (existing && existing.status === 'Evaluated') {
    return res.status(400).json({ error: 'This submission has already been evaluated and cannot be overwritten.' });
  }

  if (existing) {
    db.prepare('UPDATE submissions SET notes = ?, fileName = ?, filePath = ?, submittedAt = ? WHERE id = ?').run(
      String(notes || '').trim(),
      fileName || existing.fileName,
      filePath || existing.filePath,
      now,
      existing.id
    );
    return res.json({ id: existing.id, message: 'Submission updated successfully.' });
  }

  const id = generateId('subm');
  db.prepare(`
    INSERT INTO submissions (id, assignmentId, studentId, studentName, rollNumber, notes, fileName, filePath, submittedAt, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Submitted')
  `).run(
    id,
    assignment.id,
    user.id,
    user.fullName,
    user.rollNumber || user.universityId,
    String(notes || '').trim(),
    fileName || null,
    filePath || null,
    now
  );
  res.status(201).json({ id, message: 'Assignment submitted successfully.' });
});

app.get('/api/assignments/:id/submissions', requireAuth, requireRole('faculty', 'admin'), (req, res) => {
  const rows = db
    .prepare('SELECT * FROM submissions WHERE assignmentId = ? ORDER BY submittedAt DESC')
    .all(req.params.id)
    .map((s: any) => ({
      ...s,
      fileUrl: s.filePath ? `/api/files/${encodeURIComponent(s.filePath)}` : null,
    }));
  res.json({ submissions: rows });
});

app.put('/api/submissions/:id/evaluate', requireAuth, requireRole('faculty', 'admin'), (req: AuthenticatedRequest, res) => {
  const { marks, feedback } = req.body || {};
  if (marks === undefined || marks === null || Number.isNaN(Number(marks))) {
    return res.status(400).json({ error: 'Numeric marks are required.' });
  }
  const sub = db.prepare('SELECT * FROM submissions WHERE id = ?').get(req.params.id) as any;
  if (!sub) return res.status(404).json({ error: 'Submission not found.' });

  const now = new Date().toISOString();
  db.prepare(`
    UPDATE submissions SET status = 'Evaluated', marks = ?, feedback = ?, evaluatedBy = ?, evaluatedAt = ?
    WHERE id = ?
  `).run(Number(marks), String(feedback || '').trim(), req.user!.fullName, now, sub.id);

  createNotification(
    sub.studentId,
    'Assignment Evaluated',
    `Your submission was graded: ${marks} marks. ${feedback ? `Feedback: ${feedback}` : ''}`,
    'assignment',
    'assignments'
  );
  res.json({ ok: true });
});

// ==================== EXAMINATIONS ====================
app.get('/api/examinations', requireAuth, (req: AuthenticatedRequest, res) => {
  const user = req.user!;
  let rows: any[] = [];
  if (user.role === 'student') {
    rows = db
      .prepare('SELECT * FROM examinations WHERE department = ? AND semester = ? ORDER BY examDate ASC')
      .all(user.departmentName, user.semester || 6) as any[];
    if (rows.length === 0) {
      rows = db
        .prepare('SELECT * FROM examinations WHERE department = ? ORDER BY examDate ASC')
        .all(user.departmentName) as any[];
    }
    if (rows.length === 0) {
      rows = db
        .prepare("SELECT * FROM examinations WHERE department = 'Computer Science and Engineering' ORDER BY examDate ASC")
        .all() as any[];
    }
  } else {
    rows = db.prepare('SELECT * FROM examinations ORDER BY examDate ASC').all() as any[];
  }

  res.json({
    examinations: rows.map((e) => ({
      ...e,
      resultPublished: Boolean(e.resultPublished),
    })),
  });
});

app.post('/api/examinations', requireAuth, requireRole('faculty', 'admin'), (req: AuthenticatedRequest, res) => {
  const { examName, subjectId, semester, examDate, startTime, endTime, examType, room, instructions } = req.body || {};
  if (!examName || !subjectId || !semester || !examDate || !startTime || !endTime || !examType || !room) {
    return res.status(400).json({ error: 'All examination schedule fields are required.' });
  }
  const subject = db.prepare('SELECT * FROM subjects WHERE id = ?').get(subjectId) as any;
  if (!subject) return res.status(404).json({ error: 'Subject not found.' });

  const id = generateId('exm');
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO examinations (id, examName, subjectId, subjectCode, subjectName, department, semester, examDate, startTime, endTime, examType, room, instructions, resultPublished, resultsSummary, createdBy, createdAt)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, ?)
  `).run(
    id,
    String(examName).trim(),
    subject.id,
    subject.code,
    subject.name,
    subject.departmentName,
    Number(semester),
    examDate,
    startTime,
    endTime,
    examType,
    room,
    String(instructions || '').trim(),
    req.user!.fullName,
    now
  );

  const students = db
    .prepare('SELECT id FROM users WHERE role = ? AND departmentName = ? AND semester = ?')
    .all('student', subject.departmentName, Number(semester)) as any[];
  for (const s of students) {
    createNotification(
      s.id,
      `Exam Scheduled: ${subject.code}`,
      `${examName} on ${examDate} (${startTime}–${endTime}) at ${room}.`,
      'examination',
      'examinations'
    );
  }

  res.status(201).json({ id });
});

app.put('/api/examinations/:id/publish-result', requireAuth, requireRole('faculty', 'admin'), (req, res) => {
  const { resultsSummary } = req.body || {};
  db.prepare('UPDATE examinations SET resultPublished = 1, resultsSummary = ? WHERE id = ?').run(
    String(resultsSummary || 'Results published on academic portal.').trim(),
    req.params.id
  );
  res.json({ ok: true });
});

// ==================== PLACEMENT PORTAL & APPLICATIONS ====================
app.get('/api/companies', requireAuth, (_req, res) => {
  res.json({ companies: db.prepare('SELECT * FROM companies ORDER BY name ASC').all() });
});

app.post('/api/companies', requireAuth, requireRole('coordinator', 'admin'), (req, res) => {
  const { name, industry, website, description } = req.body || {};
  if (!name || !industry) {
    return res.status(400).json({ error: 'Company name and industry are required.' });
  }
  const initials = String(name)
    .split(/\s+/)
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase() || '')
    .join('');
  const id = generateId('comp');
  db.prepare('INSERT INTO companies (id, name, industry, website, logoInitials, description, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
    id,
    String(name).trim(),
    String(industry).trim(),
    String(website || '').trim(),
    initials || 'CO',
    String(description || '').trim(),
    new Date().toISOString()
  );
  res.status(201).json({ id });
});

app.get('/api/placements', requireAuth, (req: AuthenticatedRequest, res) => {
  const user = req.user!;
  const rows = db.prepare('SELECT * FROM placements ORDER BY deadline ASC').all() as any[];

  const placements = rows.map((p) => {
    const parsed = {
      ...p,
      eligibleBranches: JSON.parse(p.eligibleBranchesJson || '[]'),
      requiredSkills: JSON.parse(p.requiredSkillsJson || '[]'),
      selectionProcess: JSON.parse(p.selectionProcessJson || '[]'),
      criteriaConfigured: Boolean(p.criteriaConfigured),
    };
    const eligibility = user.role === 'student' ? evaluatePlacementEligibility(user, parsed) : undefined;
    const myAppRow =
      user.role === 'student'
        ? (db.prepare('SELECT * FROM applications WHERE placementId = ? AND studentId = ?').get(p.id, user.id) as any)
        : null;

    return {
      ...parsed,
      eligibility,
      myApplication: myAppRow
        ? {
            ...myAppRow,
            skills: JSON.parse(myAppRow.skillsJson || '[]'),
            statusHistory: JSON.parse(myAppRow.statusHistoryJson || '[]'),
            resumeUrl: `/api/files/${encodeURIComponent(myAppRow.resumePath)}`,
          }
        : null,
    };
  });

  res.json({ placements });
});

app.post('/api/placements', requireAuth, requireRole('coordinator', 'admin'), (req: AuthenticatedRequest, res) => {
  const {
    companyId,
    roleTitle,
    description,
    packageLpa,
    eligibleBranches,
    minCgpa,
    maxBacklogs,
    graduationYear,
    requiredSkills,
    additionalConditions,
    deadline,
    selectionProcess,
  } = req.body || {};

  if (!companyId || !roleTitle || !description || !packageLpa || !deadline) {
    return res.status(400).json({ error: 'Company, job role, description, salary package, and deadline are required.' });
  }

  const company = db.prepare('SELECT * FROM companies WHERE id = ?').get(companyId) as any;
  if (!company) return res.status(404).json({ error: 'Company not found.' });

  const branchesArr = Array.isArray(eligibleBranches)
    ? eligibleBranches.map((b) => String(b).trim()).filter(Boolean)
    : [];
  const parsedMinCgpa = minCgpa !== '' && minCgpa !== null && minCgpa !== undefined ? Number(minCgpa) : null;
  const parsedMaxBacklogs = maxBacklogs !== '' && maxBacklogs !== null && maxBacklogs !== undefined ? Number(maxBacklogs) : null;
  const parsedGradYear = graduationYear !== '' && graduationYear !== null && graduationYear !== undefined ? Number(graduationYear) : null;
  const criteriaConfigured =
    branchesArr.length > 0 || parsedMinCgpa !== null || parsedMaxBacklogs !== null || parsedGradYear !== null ? 1 : 0;

  const id = generateId('plc');
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO placements (
      id, companyId, companyName, logoInitials, roleTitle, description, packageLpa,
      eligibleBranchesJson, minCgpa, maxBacklogs, graduationYear, requiredSkillsJson,
      additionalConditions, criteriaConfigured, deadline, selectionProcessJson, createdBy, createdAt
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    company.id,
    company.name,
    company.logoInitials,
    String(roleTitle).trim(),
    String(description).trim(),
    String(packageLpa).trim(),
    JSON.stringify(branchesArr),
    parsedMinCgpa,
    parsedMaxBacklogs,
    parsedGradYear,
    JSON.stringify(Array.isArray(requiredSkills) ? requiredSkills : []),
    additionalConditions ? String(additionalConditions).trim() : null,
    criteriaConfigured,
    deadline,
    JSON.stringify(Array.isArray(selectionProcess) && selectionProcess.length > 0 ? selectionProcess : ['Application Review', 'Technical Assessment', 'Interview', 'Offer']),
    req.user!.fullName,
    now
  );

  // Notify students
  const students = db.prepare("SELECT id FROM users WHERE role = 'student'").all() as any[];
  for (const s of students) {
    createNotification(
      s.id,
      `New Placement Drive: ${company.name}`,
      `${roleTitle} (${packageLpa}) — Apply before ${deadline}.`,
      'placement',
      'placements'
    );
  }

  res.status(201).json({ id });
});

app.post('/api/placements/:id/apply', requireAuth, requireRole('student'), (req: AuthenticatedRequest, res) => {
  const user = req.user!;
  const placementRow = db.prepare('SELECT * FROM placements WHERE id = ?').get(req.params.id) as any;
  if (!placementRow) return res.status(404).json({ error: 'Placement opportunity not found.' });

  const placement = {
    ...placementRow,
    eligibleBranches: JSON.parse(placementRow.eligibleBranchesJson || '[]'),
    requiredSkills: JSON.parse(placementRow.requiredSkillsJson || '[]'),
    selectionProcess: JSON.parse(placementRow.selectionProcessJson || '[]'),
    criteriaConfigured: Boolean(placementRow.criteriaConfigured),
  };

  // Server-side duplicate check
  const existing = db
    .prepare('SELECT id, applicationCode FROM applications WHERE placementId = ? AND studentId = ?')
    .get(placement.id, user.id) as any;
  if (existing) {
    return res.status(409).json({
      error: `Duplicate application prevented. You have already applied to this opportunity (Application ID: ${existing.applicationCode}).`,
    });
  }

  // Deadline check
  if (new Date(`${placement.deadline}T23:59:59`).getTime() < Date.now()) {
    return res.status(400).json({ error: 'The application deadline for this placement drive has passed.' });
  }

  // Server-side eligibility enforcement
  const eligibility = evaluatePlacementEligibility(user, placement);
  if (!eligibility.eligible) {
    return res.status(403).json({
      error: `You are not eligible to submit this application: ${eligibility.reasons.join(' ')}`,
    });
  }

  const {
    fullName,
    rollNumber,
    email,
    phone,
    department,
    branch,
    cgpa,
    graduationYear,
    skills,
    projectsText,
    personalNotes,
    resumeFileName,
    resumePath,
    confirmed,
  } = req.body || {};

  if (!confirmed) {
    return res.status(400).json({ error: 'Please review and confirm your application before submitting.' });
  }
  if (!fullName || !rollNumber || !email || !phone || !department || !branch || !projectsText || !resumeFileName || !resumePath) {
    return res.status(400).json({ error: 'All application fields and a PDF resume upload are required.' });
  }

  const safePath = path.basename(String(resumePath));
  if (!fs.existsSync(path.join(uploadsDir, safePath))) {
    return res.status(400).json({ error: 'Uploaded resume file could not be verified on the server. Please re-upload.' });
  }

  const now = new Date().toISOString();
  const appId = generateId('app');
  const applicationCode = `APP-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`;
  const history = [
    {
      status: 'Application Submitted',
      updatedAt: now,
      updatedBy: String(fullName).trim(),
      note: 'Application and PDF resume submitted by student.',
    },
  ];

  db.prepare(`
    INSERT INTO applications (
      id, applicationCode, placementId, studentId, studentName, rollNumber, email, phone,
      department, branch, cgpa, graduationYear, skillsJson, projectsText, personalNotes,
      resumeFileName, resumePath, status, statusHistoryJson, submittedAt, updatedAt
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Application Submitted', ?, ?, ?)
  `).run(
    appId,
    applicationCode,
    placement.id,
    user.id,
    String(fullName).trim(),
    String(rollNumber).trim(),
    String(email).trim(),
    String(phone).trim(),
    String(department).trim(),
    String(branch).trim(),
    Number.isFinite(Number(cgpa)) ? Number(cgpa) : 0,
    Number.isFinite(Number(graduationYear)) ? Number(graduationYear) : 2027,
    JSON.stringify(Array.isArray(skills) ? skills : []),
    String(projectsText).trim(),
    String(personalNotes || '').trim(),
    String(resumeFileName).trim(),
    safePath,
    JSON.stringify(history),
    now,
    now
  );

  createNotification(
    user.id,
    `Application Confirmed: ${placement.companyName}`,
    `Your application ${applicationCode} for ${placement.roleTitle} has been recorded.`,
    'application',
    'placements'
  );

  res.status(201).json({
    application: {
      id: appId,
      applicationCode,
      status: 'Application Submitted',
      submittedAt: now,
    },
  });
});

app.get('/api/applications', requireAuth, (req: AuthenticatedRequest, res) => {
  const user = req.user!;
  const query =
    user.role === 'student'
      ? `SELECT app.*, p.companyName, p.roleTitle, p.packageLpa
         FROM applications app
         JOIN placements p ON p.id = app.placementId
         WHERE app.studentId = ?
         ORDER BY app.updatedAt DESC`
      : `SELECT app.*, p.companyName, p.roleTitle, p.packageLpa
         FROM applications app
         JOIN placements p ON p.id = app.placementId
         ORDER BY app.updatedAt DESC`;

  const rows = (user.role === 'student' ? db.prepare(query).all(user.id) : db.prepare(query).all()) as any[];
  res.json({
    applications: rows.map((r) => ({
      ...r,
      skills: JSON.parse(r.skillsJson || '[]'),
      statusHistory: JSON.parse(r.statusHistoryJson || '[]'),
      resumeUrl: `/api/files/${encodeURIComponent(r.resumePath)}`,
    })),
  });
});

app.put('/api/applications/:id/status', requireAuth, requireRole('coordinator', 'admin'), (req: AuthenticatedRequest, res) => {
  const { status, note } = req.body || {};
  const validStatuses: ApplicationStatus[] = [
    'Application Submitted',
    'Under Review',
    'Online Assessment',
    'Technical Interview',
    'HR Interview',
    'Selected',
    'Rejected',
    'Offer Received',
  ];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ error: 'Invalid application status.' });
  }
  const appRow = db
    .prepare(
      `SELECT a.*, p.companyName, p.roleTitle FROM applications a JOIN placements p ON p.id = a.placementId WHERE a.id = ?`
    )
    .get(req.params.id) as any;
  if (!appRow) return res.status(404).json({ error: 'Application not found.' });

  const now = new Date().toISOString();
  const history = JSON.parse(appRow.statusHistoryJson || '[]');
  history.push({
    status,
    updatedAt: now,
    updatedBy: req.user!.fullName,
    note: String(note || '').trim() || undefined,
  });

  db.prepare('UPDATE applications SET status = ?, statusHistoryJson = ?, updatedAt = ? WHERE id = ?').run(
    status,
    JSON.stringify(history),
    now,
    appRow.id
  );

  createNotification(
    appRow.studentId,
    `Application Status Updated: ${appRow.companyName}`,
    `Application ${appRow.applicationCode} (${appRow.roleTitle}) is now "${status}".`,
    'application',
    'placements'
  );

  res.json({ ok: true, status, statusHistory: history });
});

// ==================== COLLEGE EVENTS & REGISTRATIONS ====================
app.get('/api/events', requireAuth, (req: AuthenticatedRequest, res) => {
  const user = req.user!;
  const rows = db.prepare('SELECT * FROM events ORDER BY eventDate ASC').all() as any[];
  const events = rows.map((ev) => {
    const reg = db
      .prepare('SELECT * FROM event_registrations WHERE eventId = ? AND userId = ?')
      .get(ev.id, user.id) as any;
    return {
      ...ev,
      myRegistration: reg || null,
    };
  });
  res.json({ events });
});

app.post('/api/events', requireAuth, requireRole('faculty', 'admin', 'coordinator'), (req: AuthenticatedRequest, res) => {
  const { title, posterKey, description, category, organizer, eventDate, eventTime, venue, deadline, maxSeats } = req.body || {};
  if (!title || !description || !category || !organizer || !eventDate || !eventTime || !venue || !deadline || !maxSeats) {
    return res.status(400).json({ error: 'All event fields are required.' });
  }
  const id = generateId('evt');
  db.prepare(`
    INSERT INTO events (id, title, posterKey, description, category, organizer, eventDate, eventTime, venue, deadline, maxSeats, registeredCount, createdBy, createdAt)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
  `).run(
    id,
    String(title).trim(),
    posterKey || 'seminar',
    String(description).trim(),
    category,
    String(organizer).trim(),
    eventDate,
    eventTime,
    String(venue).trim(),
    deadline,
    Number(maxSeats),
    req.user!.fullName,
    new Date().toISOString()
  );
  res.status(201).json({ id });
});

app.post('/api/events/:id/register', requireAuth, (req: AuthenticatedRequest, res) => {
  const user = req.user!;
  const { fullName, identifier, email, phone, department, branch, academicYear, section, confirmed } = req.body || {};

  if (!confirmed) {
    return res.status(400).json({ error: 'Please review the registration summary and confirm submission.' });
  }
  if (!fullName || !identifier || !email || !phone || !department || !branch || !academicYear) {
    return res.status(400).json({ error: 'All required registration form fields must be completed.' });
  }

  const registerTx = db.transaction(() => {
    const ev = db.prepare('SELECT * FROM events WHERE id = ?').get(req.params.id) as any;
    if (!ev) throw new Error('NOT_FOUND:Event not found.');

    const dup = db
      .prepare('SELECT registrationCode FROM event_registrations WHERE eventId = ? AND userId = ?')
      .get(ev.id, user.id) as any;
    if (dup) {
      throw new Error(`DUPLICATE:You are already registered for this event (Registration ID: ${dup.registrationCode}).`);
    }

    if (new Date(`${ev.deadline}T23:59:59`).getTime() < Date.now()) {
      throw new Error('CLOSED:Registration deadline for this event has passed.');
    }

    if (ev.registeredCount >= ev.maxSeats) {
      throw new Error('FULL:No available seats remaining for this event.');
    }

    const regId = generateId('ereg');
    const registrationCode = `EVT-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`;
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO event_registrations (id, registrationCode, eventId, userId, fullName, identifier, email, phone, department, branch, academicYear, section, registeredAt)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      regId,
      registrationCode,
      ev.id,
      user.id,
      String(fullName).trim(),
      String(identifier).trim(),
      String(email).trim(),
      String(phone).trim(),
      String(department).trim(),
      String(branch).trim(),
      String(academicYear).trim(),
      section ? String(section).trim().toUpperCase() : null,
      now
    );

    db.prepare('UPDATE events SET registeredCount = registeredCount + 1 WHERE id = ?').run(ev.id);

    createNotification(
      user.id,
      `Event Registration Confirmed`,
      `Registered for "${ev.title}" on ${ev.eventDate}. Registration ID: ${registrationCode}`,
      'event',
      'events'
    );

    return { id: regId, registrationCode, eventTitle: ev.title, registeredAt: now };
  });

  try {
    const registration = registerTx();
    res.status(201).json({ registration });
  } catch (err: any) {
    const msg = String(err.message || '');
    if (msg.startsWith('NOT_FOUND:')) return res.status(404).json({ error: msg.slice(10) });
    if (msg.startsWith('DUPLICATE:')) return res.status(409).json({ error: msg.slice(10) });
    if (msg.startsWith('CLOSED:') || msg.startsWith('FULL:')) return res.status(400).json({ error: msg.split(':').slice(1).join(':') });
    res.status(400).json({ error: 'Unable to complete registration.' });
  }
});

app.get('/api/my-event-registrations', requireAuth, (req: AuthenticatedRequest, res) => {
  const rows = db
    .prepare(
      `SELECT r.*, e.title as eventTitle, e.eventDate, e.eventTime, e.venue, e.category
       FROM event_registrations r
       JOIN events e ON e.id = r.eventId
       WHERE r.userId = ?
       ORDER BY e.eventDate ASC`
    )
    .all(req.user!.id);
  res.json({ registrations: rows });
});

app.get('/api/events/:id/registrations', requireAuth, requireRole('faculty', 'admin', 'coordinator'), (req, res) => {
  const rows = db
    .prepare('SELECT * FROM event_registrations WHERE eventId = ? ORDER BY registeredAt DESC')
    .all(req.params.id);
  res.json({ registrations: rows });
});

// ==================== ANNOUNCEMENTS ====================
app.get('/api/announcements', requireAuth, (req: AuthenticatedRequest, res) => {
  const user = req.user!;
  const all = db.prepare('SELECT * FROM announcements ORDER BY createdAt DESC').all() as any[];
  const reads = new Set(
    (db.prepare('SELECT announcementId FROM announcement_reads WHERE userId = ?').all(user.id) as any[]).map(
      (r) => r.announcementId
    )
  );

  const visible = all
    .filter((a) => {
      if (user.role === 'admin') return true;
      const roleMatch = a.targetRole === 'ALL' || a.targetRole === user.role;
      const deptMatch = a.targetDepartment === 'ALL' || a.targetDepartment === user.departmentName;
      const semMatch =
        user.role !== 'student' || a.targetSemester === 'ALL' || Number(a.targetSemester) === user.semester;
      const secMatch =
        user.role !== 'student' || a.targetSection === 'ALL' || a.targetSection === user.section;
      return roleMatch && deptMatch && semMatch && secMatch;
    })
    .map((a) => ({
      ...a,
      isRead: reads.has(a.id),
    }));

  res.json({ announcements: visible });
});

app.post('/api/announcements', requireAuth, requireRole('faculty', 'admin', 'coordinator'), (req: AuthenticatedRequest, res) => {
  const { title, content, category, priority, targetDepartment, targetSemester, targetSection, targetRole } = req.body || {};
  if (!title || !content || !category) {
    return res.status(400).json({ error: 'Title, content, and category are required.' });
  }
  const id = generateId('ann');
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO announcements (id, title, content, category, priority, targetDepartment, targetSemester, targetSection, targetRole, authorId, authorName, authorRole, createdAt)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    String(title).trim(),
    String(content).trim(),
    category,
    priority || 'Normal',
    targetDepartment || 'ALL',
    targetSemester || 'ALL',
    targetSection || 'ALL',
    targetRole || 'ALL',
    req.user!.id,
    req.user!.fullName,
    req.user!.role,
    now
  );

  // Fan out notifications to matching users
  const users = db.prepare('SELECT id, role, departmentName, semester, section FROM users WHERE id != ?').all(req.user!.id) as any[];
  for (const u of users) {
    const roleMatch = !targetRole || targetRole === 'ALL' || targetRole === u.role;
    const deptMatch = !targetDepartment || targetDepartment === 'ALL' || targetDepartment === u.departmentName;
    const semMatch = u.role !== 'student' || !targetSemester || targetSemester === 'ALL' || Number(targetSemester) === u.semester;
    const secMatch = u.role !== 'student' || !targetSection || targetSection === 'ALL' || targetSection === u.section;
    if (roleMatch && deptMatch && semMatch && secMatch) {
      createNotification(u.id, `Announcement: ${title}`, `${category} from ${req.user!.fullName}`, 'announcement', 'announcements');
    }
  }

  res.status(201).json({ id });
});

app.post('/api/announcements/:id/read', requireAuth, (req: AuthenticatedRequest, res) => {
  db.prepare(
    'INSERT OR IGNORE INTO announcement_reads (announcementId, userId, readAt) VALUES (?, ?, ?)'
  ).run(req.params.id, req.user!.id, new Date().toISOString());
  res.json({ ok: true });
});

// ==================== INTEGRATED CALENDAR ====================
app.get('/api/calendar', requireAuth, (req: AuthenticatedRequest, res) => {
  const user = req.user!;
  const items: CalendarItem[] = [];

  // Assignments
  const assignments =
    user.role === 'student'
      ? (db
          .prepare(
            `SELECT * FROM assignments
             WHERE (department = ? OR department = 'ALL')
               AND (semester = ? OR semester = 0)
               AND (section = ? OR section = 'ALL')`
          )
          .all(user.departmentName, user.semester || 6, user.section || 'A') as any[])
      : (db.prepare('SELECT * FROM assignments').all() as any[]);
  for (const a of assignments) {
    items.push({
      id: `cal_asg_${a.id}`,
      title: `${a.subjectCode}: ${a.title} (Due)`,
      date: String(a.deadline).slice(0, 10),
      time: String(a.deadline).slice(11, 16) || '23:59',
      category: 'Assignment',
      description: a.description,
      sourceModule: 'assignments',
    });
  }

  // Examinations
  let exams: any[] = [];
  if (user.role === 'student') {
    exams = db
      .prepare('SELECT * FROM examinations WHERE department = ? AND semester = ?')
      .all(user.departmentName, user.semester || 6) as any[];
    if (exams.length === 0) {
      exams = db.prepare('SELECT * FROM examinations WHERE department = ?').all(user.departmentName) as any[];
    }
    if (exams.length === 0) {
      exams = db
        .prepare("SELECT * FROM examinations WHERE department = 'Computer Science and Engineering'")
        .all() as any[];
    }
  } else {
    exams = db.prepare('SELECT * FROM examinations').all() as any[];
  }
  for (const e of exams) {
    items.push({
      id: `cal_exm_${e.id}`,
      title: `${e.subjectCode} ${e.examType}: ${e.examName}`,
      date: e.examDate,
      time: e.startTime,
      endTime: e.endTime,
      category: 'Examination',
      location: e.room,
      description: e.instructions,
      sourceModule: 'examinations',
    });
  }

  // Events
  const events = db.prepare('SELECT * FROM events').all() as any[];
  for (const ev of events) {
    items.push({
      id: `cal_evt_${ev.id}`,
      title: ev.title,
      date: ev.eventDate,
      time: ev.eventTime,
      category: 'Event',
      location: ev.venue,
      description: `${ev.category} · ${ev.organizer}`,
      sourceModule: 'events',
    });
  }

  // Placements
  const placements = db.prepare('SELECT * FROM placements').all() as any[];
  for (const p of placements) {
    items.push({
      id: `cal_plc_${p.id}`,
      title: `${p.companyName} (${p.roleTitle}) Deadline`,
      date: p.deadline,
      time: '23:59',
      category: 'Placement',
      description: `Package: ${p.packageLpa}`,
      sourceModule: 'placements',
    });
  }

  // Custom calendar events
  const custom = db.prepare('SELECT * FROM calendar_events').all() as any[];
  for (const c of custom) {
    items.push({
      id: c.id,
      title: c.title,
      date: c.eventDate,
      time: c.startTime,
      endTime: c.endTime,
      category: c.category,
      location: c.location,
      description: c.description,
      sourceModule: 'calendar',
    });
  }

  items.sort((a, b) => a.date.localeCompare(b.date));
  res.json({ items });
});

app.post('/api/calendar', requireAuth, requireRole('faculty', 'admin', 'coordinator'), (req: AuthenticatedRequest, res) => {
  const { title, eventDate, startTime, endTime, category, location, description } = req.body || {};
  if (!title || !eventDate || !category) {
    return res.status(400).json({ error: 'Title, date, and category are required.' });
  }
  const id = generateId('cal');
  db.prepare(`
    INSERT INTO calendar_events (id, title, eventDate, startTime, endTime, category, location, description, createdBy, createdAt)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    String(title).trim(),
    eventDate,
    startTime || null,
    endTime || null,
    category,
    location || null,
    description || null,
    req.user!.fullName,
    new Date().toISOString()
  );
  res.status(201).json({ id });
});

// ==================== NOTIFICATIONS & GLOBAL SEARCH ====================
app.get('/api/notifications', requireAuth, (req: AuthenticatedRequest, res) => {
  const rows = db
    .prepare('SELECT * FROM notifications WHERE userId = ? ORDER BY createdAt DESC LIMIT 50')
    .all(req.user!.id) as any[];
  res.json({
    notifications: rows.map((n) => ({ ...n, isRead: Boolean(n.isRead) })),
    unreadCount: rows.filter((n) => !n.isRead).length,
  });
});

app.put('/api/notifications/:id/read', requireAuth, (req: AuthenticatedRequest, res) => {
  db.prepare('UPDATE notifications SET isRead = 1 WHERE id = ? AND userId = ?').run(req.params.id, req.user!.id);
  res.json({ ok: true });
});

app.put('/api/notifications/read-all', requireAuth, (req: AuthenticatedRequest, res) => {
  db.prepare('UPDATE notifications SET isRead = 1 WHERE userId = ?').run(req.user!.id);
  res.json({ ok: true });
});

app.get('/api/search', requireAuth, (req: AuthenticatedRequest, res) => {
  const q = String(req.query.q || '').trim().toLowerCase();
  if (!q) return res.json({ results: [] });

  const results: { type: string; title: string; subtitle: string; module: string }[] = [];

  const announcements = db.prepare('SELECT title, category FROM announcements').all() as any[];
  for (const a of announcements) {
    if (a.title.toLowerCase().includes(q) || a.category.toLowerCase().includes(q)) {
      results.push({ type: 'Announcement', title: a.title, subtitle: a.category, module: 'announcements' });
    }
  }

  const events = db.prepare('SELECT title, category, eventDate, venue FROM events').all() as any[];
  for (const e of events) {
    if (e.title.toLowerCase().includes(q) || e.category.toLowerCase().includes(q) || e.venue.toLowerCase().includes(q)) {
      results.push({ type: 'Event', title: e.title, subtitle: `${e.category} · ${e.eventDate}`, module: 'events' });
    }
  }

  const placements = db.prepare('SELECT companyName, roleTitle, packageLpa FROM placements').all() as any[];
  for (const p of placements) {
    if (p.companyName.toLowerCase().includes(q) || p.roleTitle.toLowerCase().includes(q)) {
      results.push({ type: 'Placement', title: `${p.companyName} — ${p.roleTitle}`, subtitle: p.packageLpa, module: 'placements' });
    }
  }

  const assignments = db.prepare('SELECT title, subjectCode, deadline FROM assignments').all() as any[];
  for (const a of assignments) {
    if (a.title.toLowerCase().includes(q) || a.subjectCode.toLowerCase().includes(q)) {
      results.push({ type: 'Assignment', title: a.title, subtitle: `${a.subjectCode} · Due ${a.deadline.slice(0, 10)}`, module: 'assignments' });
    }
  }

  const subjects = db.prepare('SELECT code, name, semester FROM subjects').all() as any[];
  for (const s of subjects) {
    if (s.code.toLowerCase().includes(q) || s.name.toLowerCase().includes(q)) {
      results.push({ type: 'Subject', title: `${s.code}: ${s.name}`, subtitle: `Semester ${s.semester}`, module: 'academics' });
    }
  }

  res.json({ results: results.slice(0, 20) });
});

// ==================== FILE UPLOADS & DOWNLOADS ====================
app.post('/api/uploads/resume', requireAuth, (req, res) => {
  resumeUpload.single('file')(req, res, (err: any) => {
    if (err) {
      return res.status(400).json({ error: err.message || 'Resume upload failed.' });
    }
    if (!req.file) {
      return res.status(400).json({ error: 'Please select a PDF resume file.' });
    }
    res.status(201).json({
      fileName: req.file.originalname,
      filePath: req.file.filename,
      fileUrl: `/api/files/${encodeURIComponent(req.file.filename)}`,
      sizeBytes: req.file.size,
    });
  });
});

app.post('/api/uploads/document', requireAuth, (req, res) => {
  docUpload.single('file')(req, res, (err: any) => {
    if (err) {
      return res.status(400).json({ error: err.message || 'Document upload failed.' });
    }
    if (!req.file) {
      return res.status(400).json({ error: 'Please select a document file.' });
    }
    res.status(201).json({
      fileName: req.file.originalname,
      filePath: req.file.filename,
      fileUrl: `/api/files/${encodeURIComponent(req.file.filename)}`,
      sizeBytes: req.file.size,
    });
  });
});

app.get('/api/files/:filename', requireAuth, (req, res) => {
  const safeName = path.basename(req.params.filename);
  const fullPath = path.join(uploadsDir, safeName);
  if (!fs.existsSync(fullPath)) {
    return res.status(404).json({ error: 'File not found.' });
  }
  res.sendFile(fullPath);
});

// ==================== GEMINI AI CAMPUS ASSISTANT ====================
app.get('/api/ai/history', requireAuth, (req: AuthenticatedRequest, res) => {
  const messages = db
    .prepare('SELECT * FROM chat_history WHERE userId = ? ORDER BY createdAt ASC LIMIT 50')
    .all(req.user!.id);
  res.json({ messages });
});

app.delete('/api/ai/history', requireAuth, (req: AuthenticatedRequest, res) => {
  db.prepare('DELETE FROM chat_history WHERE userId = ?').run(req.user!.id);
  res.json({ ok: true });
});

app.post('/api/ai/chat', requireAuth, async (req: AuthenticatedRequest, res) => {
  const user = req.user!;
  const message = String(req.body?.message || '').trim();
  if (!message) {
    return res.status(400).json({ error: 'Please enter a question for CampusCopilot AI.' });
  }

  try {
    const reply = await generateCampusAssistantReply(user, message);
    const now = new Date().toISOString();
    const userMsgId = generateId('chat');
    const aiMsgId = generateId('chat');

    db.prepare('INSERT INTO chat_history (id, userId, role, content, createdAt) VALUES (?, ?, ?, ?, ?)').run(
      userMsgId,
      user.id,
      'user',
      message,
      now
    );
    db.prepare('INSERT INTO chat_history (id, userId, role, content, createdAt) VALUES (?, ?, ?, ?, ?)').run(
      aiMsgId,
      user.id,
      'assistant',
      reply,
      new Date(Date.now() + 1).toISOString()
    );

    res.json({
      userMessage: { id: userMsgId, userId: user.id, role: 'user', content: message, createdAt: now },
      assistantMessage: { id: aiMsgId, userId: user.id, role: 'assistant', content: reply, createdAt: now },
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to generate AI response.' });
  }
});

app.post('/api/ai/chat/stream', requireAuth, async (req: AuthenticatedRequest, res) => {
  const user = req.user!;
  const message = String(req.body?.message || '').trim();
  if (!message) {
    return res.status(400).json({ error: 'Please enter a question for CampusCopilot AI.' });
  }

  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  let fullReply = '';
  try {
    for await (const delta of streamCampusAssistantReply(user, message)) {
      fullReply += delta;
      res.write(`data: ${JSON.stringify({ type: 'delta', text: delta })}\n\n`);
    }

    const reply = fullReply.trim();
    if (!reply) {
      res.write(`data: ${JSON.stringify({ type: 'error', error: 'Empty AI response. Please try again.' })}\n\n`);
      return res.end();
    }

    const now = new Date().toISOString();
    const userMsgId = generateId('chat');
    const aiMsgId = generateId('chat');

    db.prepare('INSERT INTO chat_history (id, userId, role, content, createdAt) VALUES (?, ?, ?, ?, ?)').run(
      userMsgId,
      user.id,
      'user',
      message,
      now
    );
    db.prepare('INSERT INTO chat_history (id, userId, role, content, createdAt) VALUES (?, ?, ?, ?, ?)').run(
      aiMsgId,
      user.id,
      'assistant',
      reply,
      new Date(Date.now() + 1).toISOString()
    );

    res.write(
      `data: ${JSON.stringify({
        type: 'done',
        userMessage: { id: userMsgId, userId: user.id, role: 'user', content: message, createdAt: now },
        assistantMessage: { id: aiMsgId, userId: user.id, role: 'assistant', content: reply, createdAt: now },
      })}\n\n`
    );
    res.end();
  } catch (err: any) {
    res.write(`data: ${JSON.stringify({ type: 'error', error: err.message || 'Failed to generate AI response.' })}\n\n`);
    res.end();
  }
});

// ==================== ADMIN & MANAGEMENT ENDPOINTS ====================
app.get('/api/users/students', requireAuth, requireRole('faculty', 'admin', 'coordinator'), (_req, res) => {
  const rows = db.prepare("SELECT * FROM users WHERE role = 'student' ORDER BY rollNumber ASC").all();
  res.json({ students: rows.map(mapDbUserToProfile) });
});

app.get('/api/admin/users', requireAuth, requireRole('admin'), (_req, res) => {
  const rows = db.prepare('SELECT * FROM users ORDER BY role ASC, fullName ASC').all();
  res.json({ users: rows.map(mapDbUserToProfile) });
});

app.put('/api/admin/users/:id/role', requireAuth, requireRole('admin'), (req: AuthenticatedRequest, res) => {
  const { role } = req.body || {};
  if (!['student', 'faculty', 'coordinator', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role specified.' });
  }
  if (req.params.id === req.user!.id && role !== 'admin') {
    return res.status(400).json({ error: 'You cannot revoke your own administrator role.' });
  }
  db.prepare('UPDATE users SET role = ?, updatedAt = ? WHERE id = ?').run(role, new Date().toISOString(), req.params.id);
  res.json({ ok: true });
});

app.post('/api/admin/users', requireAuth, requireRole('admin'), (req, res) => {
  const { fullName, email, password, role, universityId, departmentId, designation } = req.body || {};
  if (!fullName || !email || !password || !role || !universityId || !departmentId) {
    return res.status(400).json({ error: 'Full name, email, password, role, university ID, and department are required.' });
  }
  const dept = db.prepare('SELECT * FROM departments WHERE id = ?').get(departmentId) as any;
  if (!dept) return res.status(400).json({ error: 'Department not found.' });

  const id = generateId('usr');
  const now = new Date().toISOString();
  try {
    db.prepare(`
      INSERT INTO users (
        id, fullName, email, passwordHash, role, universityId, departmentId, departmentName,
        facultyId, designation, createdAt, updatedAt
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      String(fullName).trim(),
      String(email).trim().toLowerCase(),
      hashPassword(String(password)),
      role,
      String(universityId).trim(),
      dept.id,
      dept.name,
      role !== 'student' ? String(universityId).trim() : null,
      designation || (role === 'coordinator' ? 'Placement Coordinator' : 'Administrator'),
      now,
      now
    );
    res.status(201).json({ id });
  } catch (err: any) {
    res.status(409).json({ error: 'Email or University ID already exists.' });
  }
});

app.post('/api/admin/departments', requireAuth, requireRole('admin'), (req, res) => {
  const { code, name, headName } = req.body || {};
  if (!code || !name || !headName) {
    return res.status(400).json({ error: 'Department code, name, and head name are required.' });
  }
  const id = generateId('dept');
  try {
    db.prepare('INSERT INTO departments (id, code, name, headName, createdAt) VALUES (?, ?, ?, ?, ?)').run(
      id,
      String(code).trim().toUpperCase(),
      String(name).trim(),
      String(headName).trim(),
      new Date().toISOString()
    );
    res.status(201).json({ id });
  } catch {
    res.status(409).json({ error: 'Department code already exists.' });
  }
});

app.post('/api/admin/subjects', requireAuth, requireRole('admin'), (req, res) => {
  const { code, name, departmentId, semester, credits, type, facultyId } = req.body || {};
  if (!code || !name || !departmentId || !semester || !credits) {
    return res.status(400).json({ error: 'Code, name, department, semester, and credits are required.' });
  }
  const dept = db.prepare('SELECT * FROM departments WHERE id = ?').get(departmentId) as any;
  if (!dept) return res.status(400).json({ error: 'Department not found.' });
  const faculty = facultyId ? (db.prepare('SELECT id, fullName FROM users WHERE id = ?').get(facultyId) as any) : null;

  const id = generateId('sub');
  try {
    db.prepare(`
      INSERT INTO subjects (id, code, name, departmentId, departmentName, semester, credits, type, facultyId, facultyName)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      String(code).trim().toUpperCase(),
      String(name).trim(),
      dept.id,
      dept.name,
      Number(semester),
      Number(credits),
      type === 'Lab' ? 'Lab' : 'Theory',
      faculty?.id || null,
      faculty?.fullName || null
    );
    res.status(201).json({ id });
  } catch {
    res.status(409).json({ error: 'Subject code already exists.' });
  }
});

app.get('/api/admin/settings', requireAuth, requireRole('admin'), (_req, res) => {
  const rows = db.prepare('SELECT * FROM platform_settings ORDER BY key ASC').all();
  res.json({ settings: rows });
});

app.put('/api/admin/settings', requireAuth, requireRole('admin'), (req, res) => {
  const { key, value } = req.body || {};
  if (!key || value === undefined) {
    return res.status(400).json({ error: 'Setting key and value are required.' });
  }
  db.prepare(
    'INSERT INTO platform_settings (key, value, updatedAt) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updatedAt = excluded.updatedAt'
  ).run(String(key), String(value), new Date().toISOString());
  res.json({ ok: true });
});

// ==================== VITE / STATIC SERVING ====================
async function startServer() {
  const PORT = process.env.NODE_ENV === 'production' ? (Number(process.env.PORT) || 3000) : 3000;

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`CampusCopilot server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
