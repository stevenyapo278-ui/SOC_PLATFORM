'use strict';

// Export CSV des vues.
//
// Format choisi : séparateur `;`, fins de ligne CRLF, BOM UTF-8 en tête —
// c'est ce qu'Excel / Calc francophones ouvrent sans réglage (virgule
// décimale locale, séparateur de champs français). Les cellules ne sont
// guillemetées que si nécessaire pour rester lisibles dans un éditeur de texte.
//
// Sécurité : une valeur SentinelOne commençant par `=`, `+`, `-`, `@` serait
// interprétée comme une formule par Excel (injection de formule). On la
// neutralise avec un apostrophe, sauf si c'est déjà un nombre négatif simple.

const CSV_BOM = '\ufeff';
const CSV_SEPARATOR = ';';
const CSV_EOL = '\r\n';

const FORMULA_PREFIX = /^[=+\-@\t\r]/;
const PLAIN_NUMBER = /^-?\d+(?:[.,]\d+)?$/;

function csvCell(value) {
  if (value === null || value === undefined) return '';
  let text = String(value);
  if (FORMULA_PREFIX.test(text) && !PLAIN_NUMBER.test(text)) text = `'${text}`;
  if (/[";\r\n]/.test(text)) text = `"${text.replace(/"/g, '""')}"`;
  return text;
}

function csvLine(values) {
  return values.map(csvCell).join(CSV_SEPARATOR) + CSV_EOL;
}

// Date ISO → « YYYY-MM-DD HH:MM:SS » (UTC) : lisible dans un tableur, sans le
// « T » et le « Z » qui gênent la conversion automatique des colonnes de dates.
function csvDate(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toISOString().slice(0, 19).replace('T', ' ');
}

module.exports = { CSV_BOM, CSV_SEPARATOR, CSV_EOL, csvCell, csvLine, csvDate };
