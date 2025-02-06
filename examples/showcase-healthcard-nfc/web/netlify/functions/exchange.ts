import { Config } from '@netlify/functions'
import * as Ably from 'ably';

export default async () => {
  try {
    const ably = new Ably.Rest(process.env.ABLY_API_KEY as string);

    const c2wChannelName = crypto.randomUUID();
    const w2cChannelName = crypto.randomUUID();
    const webTokenRequest = await ably.auth.createTokenRequest({
      capability: {
        [c2wChannelName]: ['subscribe'],
        [w2cChannelName]: ['publish'],
      },
    });
    const clientTokenRequest = await ably.auth.createTokenRequest({
      capability: {
        [c2wChannelName]: ['publish'],
        [w2cChannelName]: ['subscribe'],
      },
    });

    const result = {
      webTokenRequest,
      clientTokenRequest,
      clientToWebChannel: c2wChannelName,
      webToClientChannel: w2cChannelName
    }

    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.error('Ably Token Error:', error);
    return new Response(JSON.stringify({ error: 'Failed to generate Ably token' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

export const config: Config = {
  path: "/api/exchange"
};
