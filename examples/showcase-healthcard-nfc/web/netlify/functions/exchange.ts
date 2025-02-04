import { Handler, Context, Config } from '@netlify/functions'
import * as Ably from 'ably';

function generateRandomString(length: number, chars: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'): string {
  let result = '';
  const charactersLength = chars.length;
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}

export default async () => {
  try {
    const ably = new Ably.Rest(process.env.ABLY_API_KEY as string);

    const c2wChannelName = generateRandomString(12);
    const w2cChannelName = generateRandomString(12);
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
      clientTokenRequest
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
