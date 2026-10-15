import boundaries from 'eslint-plugin-boundaries';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      '**/dist/**',
      '**/node_modules/**',
      '**/.turbo/**',
      'tests/boundaries/fixtures/**',
    ],
  },
  ...tseslint.configs.recommended,
  {
    files: ['apps/**/*.{ts,tsx,js,jsx}', 'packages/**/*.{ts,tsx,js,jsx}'],
    plugins: {
      boundaries,
    },
    settings: {
      'import/resolver': {
        typescript: {
          alwaysTryTypes: true,
          project: './tsconfig.json',
        },
        node: {
          extensions: ['.ts', '.tsx', '.js', '.jsx'],
        },
      },
      'boundaries/flag-as-external': {
        inNodeModules: false,
      },
      'boundaries/elements': [
        {
          type: 'app:web',
          pattern: 'apps/web/**',
          partialMatch: false,
        },
        {
          type: 'app:api',
          pattern: 'apps/api/**',
          partialMatch: false,
        },
        {
          type: 'app:mcp-server',
          pattern: 'apps/mcp-server/**',
          partialMatch: false,
        },
        {
          type: 'package:domain:db',
          pattern: 'packages/domain/src/db/**',
          partialMatch: false,
        },
        {
          type: 'package:domain',
          pattern: 'packages/domain/**',
          partialMatch: false,
        },
        {
          type: 'package:schemas',
          pattern: 'packages/schemas/**',
          partialMatch: false,
        },
        {
          type: 'package:shared',
          pattern: 'packages/shared/**',
          partialMatch: false,
        },
      ],
    },
    rules: {
      'boundaries/dependencies': [
        2,
        {
          default: 'allow',
          checkAllOrigins: true,
          policies: [
            // 1. apps/web must NOT import server-only domain, db, or other applications
            {
              from: { element: { type: 'app:web' } },
              disallow: [
                { to: { element: { types: { anyOf: ['package:domain', 'package:domain:db', 'app:api', 'app:mcp-server'] } } } },
                { to: { module: { source: ['@secureflow/domain', '@secureflow/domain/**', '@secureflow/api', '@secureflow/api/**', '@secureflow/mcp-server', '@secureflow/mcp-server/**'] } } },
              ],
              message: 'Frontend apps/web cannot import server-only domain, db, or other applications ({{dependency.source}})',
            },

            // 2. apps/api must NOT import domain db directly (must use service layer), web, or mcp-server
            {
              from: { element: { type: 'app:api' } },
              disallow: [
                { to: { element: { types: { anyOf: ['package:domain:db', 'app:web', 'app:mcp-server'] } } } },
                { to: { module: { source: ['@secureflow/domain/db*', '@secureflow/web*', '@secureflow/mcp-server*'] } } },
              ],
              message: 'apps/api cannot bypass domain service layer to import db directly or import other apps ({{dependency.source}})',
            },

            // 3. apps/mcp-server must NOT import domain db directly (must use service layer), web, or api
            {
              from: { element: { type: 'app:mcp-server' } },
              disallow: [
                { to: { element: { types: { anyOf: ['package:domain:db', 'app:web', 'app:api'] } } } },
                { to: { module: { source: ['@secureflow/domain/db*', '@secureflow/web*', '@secureflow/api*'] } } },
              ],
              message: 'apps/mcp-server cannot bypass domain service layer to import db directly or import other apps ({{dependency.source}})',
            },

            // 4. packages/domain must NOT reverse-import any application
            {
              from: { element: { types: { anyOf: ['package:domain', 'package:domain:db'] } } },
              disallow: [
                { to: { element: { types: { anyOf: ['app:web', 'app:api', 'app:mcp-server'] } } } },
                { to: { module: { source: ['@secureflow/web*', '@secureflow/api*', '@secureflow/mcp-server*'] } } },
              ],
              message: 'packages/domain cannot reverse-import applications ({{dependency.source}})',
            },

            // 5. packages/schemas must NOT import domain or applications
            {
              from: { element: { type: 'package:schemas' } },
              disallow: [
                { to: { element: { types: { anyOf: ['package:domain', 'package:domain:db', 'app:web', 'app:api', 'app:mcp-server'] } } } },
                { to: { module: { source: ['@secureflow/domain*', '@secureflow/web*', '@secureflow/api*', '@secureflow/mcp-server*'] } } },
              ],
              message: 'packages/schemas cannot import domain or applications ({{dependency.source}})',
            },

            // 6. packages/shared is a pure leaf package: must NOT import schemas, domain, or applications
            {
              from: { element: { type: 'package:shared' } },
              disallow: [
                { to: { element: { types: { anyOf: ['package:schemas', 'package:domain', 'package:domain:db', 'app:web', 'app:api', 'app:mcp-server'] } } } },
                { to: { module: { source: ['@secureflow/schemas*', '@secureflow/domain*', '@secureflow/web*', '@secureflow/api*', '@secureflow/mcp-server*'] } } },
              ],
              message: 'packages/shared is a leaf utility package and cannot import other workspace packages ({{dependency.source}})',
            },
          ],
        },
      ],
    },
  }
);
