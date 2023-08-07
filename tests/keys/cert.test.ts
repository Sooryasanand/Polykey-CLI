import Logger, { LogLevel, StreamHandler } from '@matrixai/logger';
import * as testUtils from '../utils';

describe('cert', () => {
  const logger = new Logger('cert test', LogLevel.WARN, [new StreamHandler()]);
  let agentDir;
  let agentPassword;
  let agentClose;
  beforeEach(async () => {
    ({ agentDir, agentPassword, agentClose } = await testUtils.setupTestAgent(
      logger,
    ));
  });
  afterEach(async () => {
    await agentClose();
  });
  testUtils.testIf(
    testUtils.isTestPlatformEmpty || testUtils.isTestPlatformDocker,
  )('cert gets the certificate', async () => {
    let { exitCode, stdout } = await testUtils.pkExec(
      ['keys', 'cert', '--format', 'json'],
      {
        env: {
          PK_NODE_PATH: agentDir,
          PK_PASSWORD: agentPassword,
        },
        cwd: agentDir,
        command: globalThis.testCmd,
      },
    );
    expect(exitCode).toBe(0);
    expect(JSON.parse(stdout)).toEqual({
      cert: expect.any(String),
    });
    const certCommand = JSON.parse(stdout).cert;
    ({ exitCode, stdout } = await testUtils.pkExec(
      ['agent', 'status', '--format', 'json'],
      {
        env: {
          PK_NODE_PATH: agentDir,
          PK_PASSWORD: agentPassword,
        },
        cwd: agentDir,
        command: globalThis.testCmd,
      },
    ));
    expect(exitCode).toBe(0);
    const certStatus = JSON.parse(stdout).certChainPEM;
    expect(certCommand).toBe(certStatus);
  });
});