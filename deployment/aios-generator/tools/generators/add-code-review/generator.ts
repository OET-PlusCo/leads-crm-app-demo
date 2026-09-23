import {
  Tree,
  formatFiles,
  generateFiles,
  readProjectConfiguration,
  logger,
  names,
} from '@nx/devkit';
import * as path from 'path';

interface AddCodeReviewSchema {
  project: string;
  testCommand?: string;
  nodeVersion?: string;
}

export default async function addCodeReviewGenerator(
  tree: Tree,
  schema: AddCodeReviewSchema
) {
  const projectConfig = readProjectConfiguration(tree, schema.project);
  const projectRoot = projectConfig.root;

  // Generate the workflow file from template
  generateFiles(
    tree,
    path.join(__dirname, 'files'),
    '.github/workflows',        // destination — org-level .github/workflows
    {
      projectName: schema.project,
      projectRoot,
      testCommand: schema.testCommand ?? '',
      nodeVersion: schema.nodeVersion ?? '20',
      tmpl: '',
    }
  );

  await formatFiles(tree);

  logger.info(`✅ Added code review workflow for project: ${schema.project}`);
  logger.info(`   Workflow: .github/workflows/code-review-${schema.project}.yml`);
  logger.info(`   Ensure GEMINI_API_KEY is set as an org secret in GitHub.`);
}
