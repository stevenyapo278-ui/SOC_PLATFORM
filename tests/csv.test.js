'use strict';

// Format des exports CSV : séparateur `;`, fins de ligne CRLF, BOM UTF-8 —
// c'est ce qu'Excel / Calc francophones ouvrent sans réglage — plus
// l'échappement des cellules et la neutralisation des formules.

const test = require('node:test');
const assert = require('node:assert/strict');
const { CSV_BOM, csvCell, csvLine, csvDate } = require('../src/services/csv');

test('csvCell : point-virgule guillemeté, guillemets doublés', () => {
  assert.equal(csvCell('Google LLC'), 'Google LLC');
  assert.equal(csvCell(null), '');
  assert.equal(csvCell(undefined), '');
  assert.equal(csvCell(42), '42');
  assert.equal(csvCell(''), '');

  assert.equal(csvCell('C:/Program Files; x86'), '"C:/Program Files; x86"');
  assert.equal(csvCell('Backup "pro"'), '"Backup ""pro"""');
  assert.equal(csvCell('ligne 1\nligne 2'), '"ligne 1\nligne 2"');
});

test('csvCell : formules Excel neutralisées, nombres intacts', () => {
  assert.equal(csvCell('=SUM(A1:A9)'), "'=SUM(A1:A9)");
  assert.equal(csvCell('@cmd'), "'@cmd");
  assert.equal(csvCell('+33 6 12 34 56 78'), "'+33 6 12 34 56 78");

  // Un chiffre négatif n'est pas une formule : il reste tel quel.
  assert.equal(csvCell('-3'), '-3');
  assert.equal(csvCell(3.5), '3.5');
});

test('csvLine / csvDate / BOM : en-têtes et dates tableur', () => {
  assert.equal(CSV_BOM, '\ufeff');
  assert.equal(csvLine(['a', 'b;c']), 'a;"b;c"\r\n');
  assert.equal(csvLine([]), '\r\n');

  assert.equal(csvDate('2026-10-26T09:05:07.000Z'), '2026-10-26 09:05:07');
  assert.equal(csvDate(null), '');
  assert.equal(csvDate('pas-une-date'), '');
});
