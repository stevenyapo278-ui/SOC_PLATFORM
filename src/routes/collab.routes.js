'use strict';

// Collaboration : dossiers d'incident locaux (attribution, statut, priorité,
// journal d'équipe, rapports joints).
//
// TOUTE cette API est une écriture LOCALE PostgreSQL — SentinelOne n'est jamais
// contacté, la console reste en lecture seule. Sans DATABASE_URL chaque route
// répond 503 avec un message français explicite (même convention que la vue
// Applications).

const express = require('express');
const multer = require('multer');
const log = require('../logger');
const { dbEnabled } = require('../db');
const { requireApiAuth } = require('../middleware/auth');

const MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024;

// Extensions acceptées pour un rapport d'incident (et le type MIME stocké :
// il est DÉRIVÉ de l'extension, jamais pris au mot du client).
const UPLOAD_TYPES = new Map([
  ['pdf', 'application/pdf'],
  ['doc', 'application/msword'],
  ['docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
  ['xls', 'application/vnd.ms-excel'],
  ['xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
  ['ppt', 'application/vnd.ms-powerpoint'],
  ['pptx', 'application/vnd.openxmlformats-officedocument.presentationml.presentation'],
  ['txt', 'text/plain'],
  ['log', 'text/plain'],
  ['csv', 'text/csv'],
  ['md', 'text/markdown'],
  ['json', 'application/json'],
  ['xml', 'application/xml'],
  ['yml', 'application/yaml'],
  ['yaml', 'application/yaml'],
  ['html', 'text/html'],
  ['png', 'image/png'],
  ['jpg', 'image/jpeg'],
  ['jpeg', 'image/jpeg'],
  ['gif', 'image/gif'],
  ['svg', 'image/svg+xml'],
  ['zip', 'application/zip'],
  ['7z', 'application/x-7z-compressed'],
]);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_ATTACHMENT_BYTES, files: 1 },
});

const router = express.Router();
router.use(requireApiAuth);

// Chargement paresseux du store : l'app doit démarrer sans pg ni base (AGENTS.md).
function loadStore() {
  if (!dbEnabled()) return null;
  try {
    return require('../db/store');
  } catch (error) {
    log.warn('Collaboration indisponible — PostgreSQL non chargé', { error: error.message });
    return null;
  }
}

function noDatabase(res) {
  return res.status(503).json({
    error: "La collaboration (dossiers d'incident) nécessite PostgreSQL (DATABASE_URL) sur cette instance.",
  });
}

function validId(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value);
}

function readText(value, max) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, max);
}

function readList(value, allowed) {
  if (typeof value !== 'string' || !value.trim()) return undefined;
  const list = value
    .split(',')
    .map((item) => item.trim())
    .filter((item) => allowed.includes(item));
  return list.length > 0 ? list : undefined;
}

// `assignee=me` est résolu côté serveur : le front n'envoie jamais un autre
// identifiant que ceux du roster pour les actions « moi ».
function readAssignee(value, user) {
  if (typeof value !== 'string' || !value.trim()) return undefined;
  const raw = value.trim();
  if (raw === 'me') return user.username;
  if (raw === 'unassigned') return 'unassigned';
  return raw.slice(0, 64);
}

// Nom de fichier : ni chemins, ni caractères de contrôle, ni surcharge — la
// sécurité du téléchargement ne dépend pas de la décence du client.
function safeFilename(value) {
  const base = String(value || '')
    .replace(/\\/g, '/')
    .split('/')
    .pop()
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .trim();
  const cleaned = base.replace(/["]/g, "'").replace(/\s+/g, ' ');
  return (cleaned || 'rapport').slice(0, 120);
}

function extensionOf(filename) {
  const dot = filename.lastIndexOf('.');
  return dot > 0 ? filename.slice(dot + 1).toLowerCase() : '';
}

// Le multer embarqué ne doit pas échouer en erreur 500 générique : on mappe
// ses codes vers des messages français (taille, champ inattendu).
function receiveFile(req, res, next) {
  upload.single('file')(req, res, (error) => {
    if (!error) return next();
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ error: 'Fichier trop volumineux : 10 Mo maximum par rapport.' });
    }
    if (error.code === 'LIMIT_UNEXPECTED_FILE') {
      return res.status(400).json({ error: 'Champ de fichier inattendu (attendu : file).' });
    }
    if (error.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({ error: 'Un seul fichier à la fois.' });
    }
    return next(error);
  });
}

async function getCaseOr404(store, res, id) {
  if (!Number.isFinite(Number(id))) {
    res.status(400).json({ error: 'Identifiant de dossier invalide.' });
    return null;
  }
  const dossier = await store.getCase(id);
  if (!dossier) {
    res.status(404).json({ error: 'Dossier introuvable.' });
    return null;
  }
  return dossier;
}

/* ── roster des techniciens ── */

router.get('/users', async (req, res, next) => {
  const store = loadStore();
  if (!store) return noDatabase(res);
  try {
    // Auto-réparation : une session ouverte avant la migration 009 n'aurait
    // pas encore de ligne dans le roster — le simple fait de consulter la
    // liste y inscrit l'utilisateur courant.
    try {
      await store.upsertAppUser({
        username: req.user.username,
        displayName: req.user.displayName,
        email: req.user.email,
        role: req.user.role,
      });
    } catch (error) {
      log.warn('Roster non mis à jour', { error: error.message });
    }
    const users = await store.listAppUsers();
    return res.json({ data: users });
  } catch (error) {
    return next(error);
  }
});

/* ── dossiers ── */

router.get('/cases/summary', async (req, res, next) => {
  const store = loadStore();
  if (!store) return noDatabase(res);
  try {
    return res.json({ data: await store.caseSummary(req.user.username) });
  } catch (error) {
    return next(error);
  }
});

router.get('/cases', async (req, res, next) => {
  const store = loadStore();
  if (!store) return noDatabase(res);
  try {
    const limit = Number.parseInt(req.query.limit, 10);
    const page = await store.listCases({
      limit: Number.isFinite(limit) && limit > 0 ? Math.min(limit, 100) : 25,
      cursor: typeof req.query.cursor === 'string' && req.query.cursor.length <= 512
        ? req.query.cursor
        : undefined,
      statuses: readList(req.query.status, store.CASE_STATUSES),
      priorities: readList(req.query.priority, store.CASE_PRIORITIES),
      assignee: readAssignee(req.query.assignee, req.user),
      threatId: validId(req.query.threatId) ? req.query.threatId : undefined,
      threatIds: typeof req.query.threatIds === 'string'
        ? req.query.threatIds.split(',').filter(validId).slice(0, 100)
        : undefined,
      query: readText(req.query.query, 200) || undefined,
    });
    return res.json(page);
  } catch (error) {
    return next(error);
  }
});

// Création = attribution d'une menace à un technicien.
router.post('/cases', async (req, res, next) => {
  const store = loadStore();
  if (!store) return noDatabase(res);
  try {
    const body = req.body || {};
    const threatId = body.threatId;
    if (!validId(threatId)) {
      return res.status(400).json({ error: 'Identifiant de menace invalide.' });
    }
    const assignee = readText(body.assignee, 64);
    if (!assignee) {
      return res.status(400).json({ error: 'Sélectionnez le technicien chargé du dossier.' });
    }
    const priority = body.priority && store.CASE_PRIORITIES.includes(body.priority) ? body.priority : 'moyenne';
    const status = body.status && store.CASE_STATUSES.includes(body.status) ? body.status : 'nouveau';

    const created = await store.createCase({ threatId, assignee, priority, status, author: req.user.username });
    if (created.error === 'threat_not_found') {
      return res.status(404).json({ error: 'Menace introuvable dans la base locale.' });
    }
    if (created.error === 'duplicate') {
      return res.status(409).json({
        error: 'Un dossier est déjà ouvert pour cette menace.',
        caseId: created.id || null,
      });
    }
    const dossier = await store.getCase(created.caseId);
    return res.status(201).json({ data: dossier });
  } catch (error) {
    return next(error);
  }
});

router.get('/cases/:id', async (req, res, next) => {
  const store = loadStore();
  if (!store) return noDatabase(res);
  try {
    const dossier = await getCaseOr404(store, res, req.params.id);
    if (!dossier) return undefined;
    const [events, attachments] = await Promise.all([
      store.listCaseEvents(dossier.id, { limit: 200 }),
      store.listCaseAttachments(dossier.id),
    ]);
    return res.json({ data: { case: dossier, events: events.data, attachments } });
  } catch (error) {
    return next(error);
  }
});

// Changement de statut, de priorité ou d'attribution — un événement de journal
// par champ modifié (avant/après).
router.patch('/cases/:id', async (req, res, next) => {
  const store = loadStore();
  if (!store) return noDatabase(res);
  try {
    const body = req.body || {};
    const changes = {};
    if (body.status !== undefined) {
      if (!store.CASE_STATUSES.includes(body.status)) {
        return res.status(400).json({ error: 'Statut de dossier invalide.' });
      }
      changes.status = body.status;
    }
    if (body.priority !== undefined) {
      if (!store.CASE_PRIORITIES.includes(body.priority)) {
        return res.status(400).json({ error: 'Priorité invalide.' });
      }
      changes.priority = body.priority;
    }
    if (body.assignee !== undefined) {
      const assignee = readText(body.assignee, 64);
      if (!assignee) {
        return res.status(400).json({ error: 'Le technicien ne peut pas être vide — clôturez le dossier pour le retirer du suivi.' });
      }
      changes.assignee = assignee;
    }
    if (Object.keys(changes).length === 0) {
      return res.status(400).json({ error: 'Aucune modification à appliquer.' });
    }

    const before = await store.getCase(req.params.id);
    if (!before) return res.status(404).json({ error: 'Dossier introuvable.' });

    const result = await store.updateCase(req.params.id, changes, req.user.username);
    if (result.error === 'not_found') return res.status(404).json({ error: 'Dossier introuvable.' });
    const dossier = await store.getCase(req.params.id);
    return res.json({ data: dossier, changed: !result.unchanged });
  } catch (error) {
    return next(error);
  }
});

/* ── commentaires ── */

router.post('/cases/:id/events', async (req, res, next) => {
  const store = loadStore();
  if (!store) return noDatabase(res);
  try {
    const body = req.body || {};
    const message = readText(body.message, 2000);
    if (!message) {
      return res.status(400).json({ error: 'Le commentaire ne peut pas être vide.' });
    }
    const event = await store.addCaseEvent(req.params.id, {
      type: 'comment',
      message,
      author: req.user.username,
    });
    if (!event) return res.status(404).json({ error: 'Dossier introuvable.' });
    return res.status(201).json({ data: event });
  } catch (error) {
    return next(error);
  }
});

/* ── rapports d'incident (pièces jointes) ── */

router.get('/cases/:id/attachments', async (req, res, next) => {
  const store = loadStore();
  if (!store) return noDatabase(res);
  try {
    const dossier = await getCaseOr404(store, res, req.params.id);
    if (!dossier) return undefined;
    return res.json({ data: await store.listCaseAttachments(dossier.id) });
  } catch (error) {
    return next(error);
  }
});

router.post('/cases/:id/attachments', receiveFile, async (req, res, next) => {
  const store = loadStore();
  if (!store) return noDatabase(res);
  try {
    const dossier = await getCaseOr404(store, res, req.params.id);
    if (!dossier) return undefined;
    if (!req.file || !req.file.buffer) {
      return res.status(400).json({ error: 'Fichier manquant (champ « file »).' });
    }

    const filename = safeFilename(req.file.originalname);
    const extension = extensionOf(filename);
    const contentType = UPLOAD_TYPES.get(extension);
    if (!contentType) {
      return res.status(400).json({
        error: `Format non autorisé (.${extension || '?'}) — extensions acceptées : ${[...UPLOAD_TYPES.keys()].join(', ')}.`,
      });
    }
    if (req.file.size === 0) {
      return res.status(400).json({ error: 'Fichier vide.' });
    }

    const result = await store.addCaseAttachment(dossier.id, {
      filename,
      contentType,
      size: req.file.size,
      data: req.file.buffer,
      uploadedBy: req.user.username,
    });
    if (result.error === 'too_many_attachments') {
      return res.status(409).json({ error: 'Limite de 20 pièces jointes atteinte pour ce dossier.' });
    }
    if (result.error === 'not_found') return res.status(404).json({ error: 'Dossier introuvable.' });
    return res.status(201).json({ data: result.attachment });
  } catch (error) {
    return next(error);
  }
});

router.get('/cases/:id/attachments/:fileId', async (req, res, next) => {
  const store = loadStore();
  if (!store) return noDatabase(res);
  try {
    const attachment = await store.getCaseAttachment(req.params.id, req.params.fileId);
    if (!attachment) return res.status(404).json({ error: 'Pièce jointe introuvable.' });

    // Toujours en téléchargement (jamais rendu inline) : un HTML joint ne peut
    // pas s'exécuter dans l'origine de la console.
    const ascii = attachment.filename.replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_');
    res.setHeader('Content-Type', attachment.contentType);
    res.setHeader('Content-Length', String(attachment.size));
    res.setHeader('Content-Disposition', `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(attachment.filename)}`);
    res.setHeader('Cache-Control', 'private, no-store');
    return res.end(attachment.data);
  } catch (error) {
    return next(error);
  }
});

router.delete('/cases/:id/attachments/:fileId', async (req, res, next) => {
  const store = loadStore();
  if (!store) return noDatabase(res);
  try {
    const dossier = await getCaseOr404(store, res, req.params.id);
    if (!dossier) return undefined;
    const attachment = await store.getCaseAttachment(dossier.id, req.params.fileId);
    if (!attachment) return res.status(404).json({ error: 'Pièce jointe introuvable.' });

    const isOwner = attachment.uploadedBy === req.user.username;
    if (!isOwner && req.user.role !== 'admin') {
      return res.status(403).json({ error: "Seul l'auteur du fichier ou un administrateur peut le supprimer." });
    }

    const removed = await store.deleteCaseAttachment(dossier.id, attachment.id, req.user.username);
    if (!removed) return res.status(404).json({ error: 'Pièce jointe introuvable.' });
    return res.json({ data: removed });
  } catch (error) {
    return next(error);
  }
});

module.exports = router;
