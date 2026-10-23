/**
 * Streaming-inference stream IDs must be unpredictable and unique per stream.
 *
 * Partial/complete/error events are routed to a stream's callbacks by string
 * equality on `streamId`, so two streams that share an ID receive each other's
 * results. The ID used to be `stream_${Date.now()}_${Math.random()…}`: two
 * streams started in the same millisecond under a fixed `Math.random` (a seeded
 * or fake-timer environment) collided, and the value was predictable.
 *
 * No socket is opened: the client is marked connected and `sendMessage` is
 * captured, so nothing touches the network.
 */
import { WebSocketClient } from '../../src/client/WebSocketClient';

type Sent = { method: string; params: any[] };

function harness(): { client: WebSocketClient; sent: Sent[] } {
  const client = new WebSocketClient({ url: 'ws://127.0.0.1:1' });
  const sent: Sent[] = [];
  (client as any).isConnected = () => true;
  (client as any).sendMessage = async (method: string, params: any[]) => {
    sent.push({ method, params });
    return undefined;
  };
  return { client, sent };
}

describe('WebSocketClient.startStreamingInference stream IDs', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('two streams started in the same millisecond under a fixed Math.random get distinct IDs', async () => {
    jest.spyOn(Date, 'now').mockReturnValue(1_700_000_000_000);
    jest.spyOn(Math, 'random').mockReturnValue(0.123456789);
    const { client, sent } = harness();

    await client.startStreamingInference({ modelId: 'm', inputData: { a: 1 } });
    await client.startStreamingInference({ modelId: 'm', inputData: { a: 2 } });

    const ids = sent.map((s) => s.params[0].streamId);
    expect(ids).toHaveLength(2);
    expect(typeof ids[0]).toBe('string');
    expect(ids[0]).not.toEqual(ids[1]);
  });

  it('a completion for one stream is not delivered to another stream started alongside it', async () => {
    jest.spyOn(Date, 'now').mockReturnValue(1_700_000_000_000);
    jest.spyOn(Math, 'random').mockReturnValue(0.5);
    const { client, sent } = harness();
    const onCompleteA = jest.fn();
    const onCompleteB = jest.fn();

    await client.startStreamingInference({ modelId: 'm', inputData: {}, onComplete: onCompleteA });
    await client.startStreamingInference({ modelId: 'm', inputData: {}, onComplete: onCompleteB });
    const idB = sent[1]!.params[0].streamId;

    client.emit('inferenceComplete', { streamId: idB, result: { output: 'for-B' } });

    expect(onCompleteB).toHaveBeenCalledTimes(1);
    expect(onCompleteA).not.toHaveBeenCalled();
  });

  it('the ID does not embed the wall clock and carries at least 128 bits of randomness', async () => {
    jest.spyOn(Date, 'now').mockReturnValue(1_700_000_000_000);
    const { client, sent } = harness();

    await client.startStreamingInference({ modelId: 'm', inputData: {} });
    const id: string = sent[0]!.params[0].streamId;

    expect(id).not.toContain('1700000000000');
    const hex = id.replace(/^stream_/, '');
    expect(hex).toMatch(/^[0-9a-f]{32,}$/);
  });
});
