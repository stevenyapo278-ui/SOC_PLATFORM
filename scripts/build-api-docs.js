'use strict';

/**
 * Génère les données statiques de la vue « Documentation API » à partir du
 * Swagger téléchargé sur la console SentinelOne.
 *
 *   Usage : node scripts/build-api-docs.js [chemin/vers/swagger.json]
 *
 * Sortie :
 *   public/api-docs-data/index.json      — catégories + sommaire des endpoints
 *   public/api-docs-data/cat/<slug>.json — détail complet d'une catégorie
 */

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const SOURCE = path.resolve(process.argv[2] || path.join(ROOT, 'formatted_swagger_2_1.json'));
const OUT_DIR = path.join(ROOT, 'public', 'api-docs-data');
const OUT_CAT_DIR = path.join(OUT_DIR, 'cat');

const slugify = (key) => key.replace(/[^a-z0-9.-]/gi, '-').toLowerCase();

function cleanParam(param) {
  const out = {
    name: param.name,
    type: param.type || 'string',
    required: Boolean(param.required),
    description: param.description || '',
  };
  if (Array.isArray(param.enum) && param.enum.length) out.enum = param.enum;
  if (param.default !== undefined) out.default = param.default;
  if (param.collectionFormat) out.collectionFormat = param.collectionFormat;
  return out;
}

function flattenSchema(nodes, prefix, out) {
  if (!Array.isArray(nodes)) return;
  for (const node of nodes) {
    if (!node || typeof node !== 'object' || !node._key) continue;
    const type = node.type || '';
    const base = `${prefix}${node._key}${type.includes('[]') ? '[]' : ''}`;
    const row = {
      path: base,
      type,
      required: Boolean(node.required),
      description: node.description || '',
    };
    if (Array.isArray(node.enum) && node.enum.length) row.enum = node.enum;
    out.push(row);
    if (Array.isArray(node._parameters) && node._parameters.length) {
      flattenSchema(node._parameters, `${base}.`, out);
    }
  }
}

function buildBody(sample) {
  if (!sample || typeof sample !== 'object') return null;
  const fields = [];
  flattenSchema(sample.schema, '', fields);
  if (!fields.length && sample.example === undefined) return null;
  return { fields, example: sample.example === undefined ? null : sample.example };
}

function buildOperation(op) {
  const parameters = {};
  for (const [location, list] of Object.entries(op.parameters || {})) {
    if (location === 'body') continue;
    if (Array.isArray(list) && list.length) parameters[location] = list.map(cleanParam);
  }

  const response = buildBody(op.responseSample);
  const body = buildBody(op.bodySample);
  const id = (op.id || '').trim();

  return {
    id,
    name: op.name,
    method: op.requestType,
    url: op.url,
    description: op.description || '',
    deprecated: Boolean(op.isDeprecated),
    download: Boolean(op.isDownload),
    permissions: op.requiredPermissions || [],
    optionalPermissions: op.optionalPermissions || [],
    responses: (op.responses || []).map((r) => ({ code: String(r.code), description: r.description || '' })),
    parameters,
    body,
    response,
  };
}

function main() {
  if (!fs.existsSync(SOURCE)) {
    console.error(`Swagger introuvable : ${SOURCE}`);
    process.exit(1);
  }

  const swagger = JSON.parse(fs.readFileSync(SOURCE, 'utf8'));
  const content = swagger.content || {};
  const apiList = Array.isArray(swagger.apiList) ? swagger.apiList : [];

  // apiList fournit l'ordre d'affichage et le nom des catégories
  const order = apiList.map((entry) => entry.key);
  const keys = [...new Set([...order, ...Object.keys(content)])];

  fs.rmSync(OUT_DIR, { recursive: true, force: true });
  fs.mkdirSync(OUT_CAT_DIR, { recursive: true });

  const index = {
    generatedAt: new Date().toISOString(),
    source: path.basename(SOURCE),
    totalCategories: 0,
    totalOperations: 0,
    categories: [],
  };

  for (const key of keys) {
    const ops = content[key];
    if (!ops || typeof ops !== 'object') continue;

    const meta = apiList.find((entry) => entry.key === key);
    const slug = slugify(key);
    const operations = Object.entries(ops)
      .map(([opKey, op]) => buildOperation({ ...op, id: opKey }))
      .sort((a, b) => a.name.localeCompare(b.name, 'en'));

    fs.writeFileSync(
      path.join(OUT_CAT_DIR, `${slug}.json`),
      JSON.stringify({ key, slug, name: meta ? meta.name : key, operations }),
    );

    index.categories.push({
      key,
      slug,
      name: meta ? meta.name : key,
      count: operations.length,
      operations: operations.map((op) => ({
        id: op.id,
        name: op.name,
        method: op.method,
        url: op.url,
        deprecated: op.deprecated,
        permissions: op.permissions,
      })),
    });
    index.totalOperations += operations.length;
  }

  index.totalCategories = index.categories.length;
  fs.writeFileSync(path.join(OUT_DIR, 'index.json'), JSON.stringify(index));

  const bytes = fs
    .readdirSync(OUT_CAT_DIR)
    .map((file) => fs.statSync(path.join(OUT_CAT_DIR, file)).size)
    .reduce((sum, size) => sum + size, 0);

  console.log(
    `API docs générées : ${index.totalCategories} catégories, ${index.totalOperations} endpoints ` +
      `(${(fs.statSync(path.join(OUT_DIR, 'index.json')).size / 1024).toFixed(0)} Ko index, ` +
      `${(bytes / 1024 / 1024).toFixed(1)} Mo détail)`,
  );
}

main();
