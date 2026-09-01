/**
 * Frequently-installed packages, used as typosquat bait references. A candidate
 * that sits one edit away from one of these — and has almost no downloads of its
 * own — is very likely a squat or an LLM misremembering the real name.
 */
export const POPULAR_NPM = [
  'react', 'react-dom', 'next', 'vue', 'svelte', 'angular', 'express', 'fastify',
  'koa', 'nest', 'axios', 'lodash', 'underscore', 'moment', 'dayjs', 'date-fns',
  'chalk', 'commander', 'yargs', 'inquirer', 'dotenv', 'zod', 'yup', 'joi',
  'valibot', 'typescript', 'eslint', 'prettier', 'jest', 'vitest', 'mocha',
  'chai', 'sinon', 'webpack', 'rollup', 'vite', 'esbuild', 'babel', 'postcss',
  'tailwindcss', 'autoprefixer', 'sass', 'less', 'styled-components', 'emotion',
  'redux', 'zustand', 'jotai', 'recoil', 'mobx', 'rxjs', 'graphql', 'apollo',
  'prisma', 'sequelize', 'typeorm', 'mongoose', 'knex', 'drizzle-orm', 'pg',
  'mysql2', 'sqlite3', 'redis', 'ioredis', 'bcrypt', 'bcryptjs', 'jsonwebtoken',
  'passport', 'cors', 'helmet', 'morgan', 'winston', 'pino', 'debug', 'uuid',
  'nanoid', 'cuid', 'classnames', 'clsx', 'ramda', 'immer', 'formik',
  'react-hook-form', 'react-router', 'react-router-dom', 'react-query',
  'swr', 'socket.io', 'ws', 'node-fetch', 'got', 'undici', 'cheerio',
  'puppeteer', 'playwright', 'selenium-webdriver', 'sharp', 'jimp', 'multer',
  'formidable', 'busboy', 'archiver', 'tar', 'glob', 'fast-glob', 'globby',
  'rimraf', 'fs-extra', 'chokidar', 'nodemon', 'concurrently', 'cross-env',
  'husky', 'lint-staged', 'semantic-release', 'stripe', 'twilio', 'nodemailer',
  'resend', 'openai', 'langchain', 'framer-motion', 'three', 'd3', 'chart.js',
  'recharts', 'plotly.js', 'leaflet', 'mapbox-gl', 'marked', 'markdown-it',
  'remark', 'rehype', 'gray-matter', 'slugify', 'validator', 'sanitize-html',
  'dompurify', 'he', 'qs', 'query-string', 'form-data', 'body-parser',
  'cookie-parser', 'express-session', 'connect-redis', 'compression',
  'http-proxy-middleware', 'async', 'bluebird', 'p-limit',
  'p-queue', 'ora', 'boxen', 'figlet', 'cli-table3', 'enquirer', 'prompts',
  'minimist', 'meow', 'execa', 'shelljs', 'zx', 'tslib', 'core-js',
  'regenerator-runtime', 'whatwg-fetch', 'abort-controller',
  'jsdom', 'happy-dom', 'cypress', 'supertest', 'msw',
  'faker', 'chance', 'nock', 'ts-node', 'tsx', 'tsup', 'unbuild',
  'microbundle', 'parcel', 'turbo', 'nx', 'lerna',
];

export const POPULAR_PYPI = [
  'requests', 'urllib3', 'numpy', 'pandas', 'scipy', 'matplotlib', 'seaborn',
  'scikit-learn', 'tensorflow', 'torch', 'transformers', 'flask', 'django',
  'fastapi', 'starlette', 'uvicorn', 'gunicorn', 'celery', 'redis', 'sqlalchemy',
  'alembic', 'psycopg2', 'pymongo', 'boto3', 'botocore', 'click', 'typer',
  'rich', 'pydantic', 'attrs', 'marshmallow', 'jinja2', 'pyyaml', 'toml',
  'python-dotenv', 'httpx', 'aiohttp', 'beautifulsoup4', 'lxml', 'selenium',
  'pillow', 'opencv-python', 'pytest', 'tox', 'black', 'flake8', 'mypy',
  'pylint', 'ruff', 'isort', 'setuptools', 'wheel', 'pip', 'poetry', 'openai',
  'anthropic', 'langchain', 'cryptography', 'pyjwt', 'passlib', 'bcrypt',
  'python-multipart', 'supabase', 'stripe', 'twilio', 'sendgrid',
];

/** Damerau-Levenshtein distance, capped: returns `max + 1` once it exceeds `max`. */
export function editDistance(a: string, b: string, max = 2): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > max) return max + 1;

  let prev2: number[] = [];
  let prev: number[] = [];
  let curr: number[] = [];
  for (let j = 0; j <= b.length; j++) prev[j] = j;

  for (let i = 1; i <= a.length; i++) {
    curr = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let value = Math.min(
        (curr[j - 1] ?? Infinity) + 1,
        (prev[j] ?? Infinity) + 1,
        (prev[j - 1] ?? Infinity) + cost,
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        value = Math.min(value, (prev2[j - 2] ?? Infinity) + 1);
      }
      curr[j] = value;
      if (value < rowMin) rowMin = value;
    }
    if (rowMin > max) return max + 1;
    prev2 = prev;
    prev = curr;
  }
  return prev[b.length] ?? max + 1;
}

/**
 * Closest popular package within `max` edits, or null.
 *
 * A name that *is* one of the popular packages is never its own lookalike, and
 * names shorter than five characters are skipped: at that length almost every
 * real package has a one-edit neighbour, so the signal is noise.
 */
export function nearestPopular(name: string, list: string[], max = 1): string | null {
  const bare = name.replace(/^@[^/]+\//, '').toLowerCase();
  if (bare.length < 5) return null;
  if (list.includes(bare)) return null;

  let best: string | null = null;
  let bestScore = max + 1;
  for (const candidate of list) {
    const d = editDistance(bare, candidate, max);
    if (d > 0 && d < bestScore) {
      bestScore = d;
      best = candidate;
    }
  }
  return best;
}
