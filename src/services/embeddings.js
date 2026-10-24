'use strict';

// Construction du texte source destiné à l'embedding (RAG), par type d'entité.
// L'appel d'embedding lui-même vit dans src/ai/embeddings.js (candidats en base).

function buildEmbeddingContent(entityType, entity) {
  if (!entity || typeof entity !== 'object') return '';
  const parts = [];
  const push = (label, value) => {
    if (value && value !== '—' && value !== '') parts.push(`${label} : ${value}`);
  };

  if (entityType === 'threat') {
    push('Menace', entity.name);
    push('Classification', entity.classification);
    push('Gravité', entity.severity);
    push('Verdict', entity.analystVerdict);
    push('Atténuation', entity.mitigationStatus);
    push('Statut', entity.incidentStatus);
    push('Endpoint', entity.agentName);
    push('Site', entity.site);
    push('Fichier', entity.filePath);
    push('Processus', entity.originatorProcess);
    push('Utilisateur', entity.processUser);
    push('Arguments', entity.maliciousProcessArguments);
    push('Storyline', entity.storyline);
    push('SHA256', entity.sha256);
  } else if (entityType === 'alert') {
    push('Alerte', entity.name);
    push('Type', entity.eventType);
    push('Gravité', entity.severity);
    push('Indicateur', entity.indicatorName);
    push('Catégorie', entity.indicatorCategory);
    push('Description', entity.indicatorDescription || entity.ruleDescription);
    push('Verdict', entity.analystVerdict);
    push('Endpoint', entity.agentName);
    push('Processus', entity.processName);
    push('Chemin', entity.processPath);
    push('Commande', entity.processCommandLine);
    push('DNS', entity.dnsRequest);
    push('Destination', entity.dstIp && entity.dstPort ? `${entity.dstIp}:${entity.dstPort}` : entity.dstIp);
    push('Storyline', entity.storyline);
    push('SHA256', entity.sha256);
  } else if (entityType === 'note') {
    push('Note', entity.text);
    push('Auteur', entity.creator);
    push('Menace', entity.threatName);
  } else if (entityType === 'activity') {
    push('Activité', entity.description);
    push('Détails', entity.details);
    push('Endpoint', entity.agentName);
    push('Utilisateur', entity.user);
  }

  return parts.join('\n');
}

module.exports = { buildEmbeddingContent };
