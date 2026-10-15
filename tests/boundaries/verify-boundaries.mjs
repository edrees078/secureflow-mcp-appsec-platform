import { ESLint } from 'eslint';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '../..');
const fixturesDir = path.join(__dirname, 'fixtures');

async function main() {
  console.log('=== SecureFlow Architectural Boundary Enforcement Test Suite ===\n');

  const eslint = new ESLint({
    cwd: projectRoot,
  });

  const testCases = [
    // --- POSITIVE TESTS (Real Workspace Source Code) ---
    {
      name: '[POSITIVE] apps/web imports @secureflow/schemas and @secureflow/shared',
      filePath: path.join(projectRoot, 'apps/web/src/index.ts'),
      code: fs.readFileSync(path.join(projectRoot, 'apps/web/src/index.ts'), 'utf-8'),
      expectViolation: false,
    },
    {
      name: '[POSITIVE] apps/api imports @secureflow/domain service and schemas',
      filePath: path.join(projectRoot, 'apps/api/src/index.ts'),
      code: fs.readFileSync(path.join(projectRoot, 'apps/api/src/index.ts'), 'utf-8'),
      expectViolation: false,
    },
    {
      name: '[POSITIVE] apps/mcp-server imports @secureflow/domain service and schemas',
      filePath: path.join(projectRoot, 'apps/mcp-server/src/index.ts'),
      code: fs.readFileSync(path.join(projectRoot, 'apps/mcp-server/src/index.ts'), 'utf-8'),
      expectViolation: false,
    },
    {
      name: '[POSITIVE] packages/domain internal service imports db repository',
      filePath: path.join(projectRoot, 'packages/domain/src/services/finding-service.ts'),
      code: fs.readFileSync(path.join(projectRoot, 'packages/domain/src/services/finding-service.ts'), 'utf-8'),
      expectViolation: false,
    },
    {
      name: '[POSITIVE] packages/schemas imports @secureflow/shared',
      filePath: path.join(projectRoot, 'packages/schemas/src/index.ts'),
      code: fs.readFileSync(path.join(projectRoot, 'packages/schemas/src/index.ts'), 'utf-8'),
      expectViolation: false,
    },

    // --- NEGATIVE TESTS (Intentional Violations from Fixtures) ---
    {
      name: '[NEGATIVE] apps/web imports server-only @secureflow/domain',
      fixtureFile: 'web-imports-domain.ts',
      simulatedLocation: path.join(projectRoot, 'apps/web/src/fixture-web-domain.ts'),
      expectViolation: true,
      expectedRule: 'boundaries/dependencies',
    },
    {
      name: '[NEGATIVE] apps/api attempts relative import of domain db bypassing service layer',
      fixtureFile: 'api-imports-db.ts',
      simulatedLocation: path.join(projectRoot, 'apps/api/src/fixture-api-db.ts'),
      expectViolation: true,
      expectedRule: 'boundaries/dependencies',
    },
    {
      name: '[NEGATIVE] apps/mcp-server attempts relative import of domain db bypassing service layer',
      fixtureFile: 'mcp-imports-db.ts',
      simulatedLocation: path.join(projectRoot, 'apps/mcp-server/src/fixture-mcp-db.ts'),
      expectViolation: true,
      expectedRule: 'boundaries/dependencies',
    },
    {
      name: '[NEGATIVE] packages/schemas reverse-imports @secureflow/domain',
      fixtureFile: 'schemas-reverse-imports-domain.ts',
      simulatedLocation: path.join(projectRoot, 'packages/schemas/src/fixture-schemas-domain.ts'),
      expectViolation: true,
      expectedRule: 'boundaries/dependencies',
    },
    {
      name: '[NEGATIVE] packages/shared imports @secureflow/schemas (violates leaf package rule)',
      fixtureFile: 'shared-imports-schemas.ts',
      simulatedLocation: path.join(projectRoot, 'packages/shared/src/fixture-shared-schemas.ts'),
      expectViolation: true,
      expectedRule: 'boundaries/dependencies',
    },
    {
      name: '[NEGATIVE] apps/web imports apps/api (cross-application forbidden)',
      fixtureFile: 'web-imports-api.ts',
      simulatedLocation: path.join(projectRoot, 'apps/web/src/fixture-web-api.ts'),
      expectViolation: true,
      expectedRule: 'boundaries/dependencies',
    },
    {
      name: '[NEGATIVE] apps/api imports apps/web (cross-application forbidden)',
      fixtureFile: 'api-imports-web.ts',
      simulatedLocation: path.join(projectRoot, 'apps/api/src/fixture-api-web.ts'),
      expectViolation: true,
      expectedRule: 'boundaries/dependencies',
    },
  ];

  let passedCount = 0;
  let failedCount = 0;

  for (const testCase of testCases) {
    const code = testCase.code ?? fs.readFileSync(path.join(fixturesDir, testCase.fixtureFile), 'utf-8');
    const targetFilePath = testCase.filePath ?? testCase.simulatedLocation;

    const results = await eslint.lintText(code, {
      filePath: targetFilePath,
    });

    const messages = results[0]?.messages ?? [];
    const boundaryViolations = messages.filter(
      (m) => m.ruleId === 'boundaries/dependencies' || m.ruleId === 'boundaries/element-types'
    );
    const syntaxErrors = messages.filter((m) => m.fatal || m.ruleId === null);

    if (syntaxErrors.length > 0) {
      console.error(`❌ FAIL: ${testCase.name}`);
      console.error(`   Encountered unexpected parse or syntax error:`, syntaxErrors);
      failedCount++;
      continue;
    }

    if (testCase.expectViolation) {
      if (boundaryViolations.length > 0) {
        const matchedRule = boundaryViolations.some((m) => m.ruleId === testCase.expectedRule);
        if (matchedRule) {
          console.log(`✅ PASS: ${testCase.name}`);
          console.log(`   Correctly rejected by '${testCase.expectedRule}':`);
          for (const v of boundaryViolations) {
            console.log(`   -> [${v.ruleId}] ${v.message}`);
          }
          passedCount++;
        } else {
          console.error(`❌ FAIL: ${testCase.name}`);
          console.error(`   Violation occurred but not with expected rule '${testCase.expectedRule}':`, boundaryViolations);
          failedCount++;
        }
      } else {
        console.error(`❌ FAIL: ${testCase.name}`);
        console.error(`   Expected boundary violation but lint succeeded! Total messages:`, messages);
        failedCount++;
      }
    } else {
      if (boundaryViolations.length === 0) {
        console.log(`✅ PASS: ${testCase.name}`);
        passedCount++;
      } else {
        console.error(`❌ FAIL: ${testCase.name}`);
        console.error(`   Unexpected boundary violation on valid code:`, boundaryViolations);
        failedCount++;
      }
    }
    console.log('');
  }

  console.log(`Summary: ${passedCount} passed, ${failedCount} failed out of ${testCases.length} tests.`);

  if (failedCount > 0) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Test runner fatal error:', err);
  process.exit(1);
});
