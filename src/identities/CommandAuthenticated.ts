import type PolykeyClient from 'polykey/dist/PolykeyClient';
import CommandPolykey from '../CommandPolykey';
import * as binOptions from '../utils/options';
import * as binUtils from '../utils';
import * as binParsers from '../utils/parsers';
import * as binProcessors from '../utils/processors';

class CommandAuthenticated extends CommandPolykey {
  constructor(...args: ConstructorParameters<typeof CommandPolykey>) {
    super(...args);
    this.name('authenticated');
    this.description('Lists all authenticated identities across all providers');
    this.option(
      '-pi, --provider-id [providerId]',
      'Digital identity provider to retrieve tokens from',
      binParsers.parseProviderId,
    );
    this.addOption(binOptions.nodeId);
    this.addOption(binOptions.clientHost);
    this.addOption(binOptions.clientPort);
    this.action(async (options) => {
      const { default: PolykeyClient } = await import(
        'polykey/dist/PolykeyClient'
      );
      const clientOptions = await binProcessors.processClientOptions(
        options.nodePath,
        options.nodeId,
        options.clientHost,
        options.clientPort,
        this.fs,
        this.logger.getChild(binProcessors.processClientOptions.name),
      );
      const auth = await binProcessors.processAuthentication(
        options.passwordFile,
        this.fs,
      );
      let pkClient: PolykeyClient;
      this.exitHandlers.handlers.push(async () => {
        if (pkClient != null) await pkClient.stop();
      });
      try {
        pkClient = await PolykeyClient.createPolykeyClient({
          nodeId: clientOptions.nodeId,
          host: clientOptions.clientHost,
          port: clientOptions.clientPort,
          options: {
            nodePath: options.nodePath,
          },
          logger: this.logger.getChild(PolykeyClient.name),
        });
        await binUtils.retryAuthentication(async (auth) => {
          const readableStream =
            await pkClient.rpcClient.methods.identitiesAuthenticatedGet({
              metadata: auth,
              providerId: options.providerId,
            });
          let head = true;
          for await (const identityMessage of readableStream) {
            const output = {
              providerId: identityMessage.providerId,
              identityId: identityMessage.identityId,
            };
            // Add a new line between entries
            if (!head) process.stdout.write('\n');
            head = false;
            process.stdout.write(
              binUtils.outputFormatter({
                type: options.format === 'json' ? 'json' : 'dict',
                data: output,
              }),
            );
          }
        }, auth);
      } finally {
        if (pkClient! != null) await pkClient.stop();
      }
    });
  }
}

export default CommandAuthenticated;
