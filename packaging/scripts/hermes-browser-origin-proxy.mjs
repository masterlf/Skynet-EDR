export async function installAuthenticatedOriginProxy(context, targetUrl, sessionToken, failures) {
  const targetOrigin = new URL(targetUrl).origin;
  await context.route('**/*', async (route) => {
    const request = route.request();
    const requestUrl = new URL(request.url());
    if (requestUrl.origin !== targetOrigin) {
      failures.push(`blocked cross-origin request: ${requestUrl.origin}`);
      await route.abort('blockedbyclient');
      return;
    }

    let response;
    try {
      response = await route.fetch({
        headers: { ...request.headers(), 'X-Hermes-Session-Token': sessionToken },
        maxRedirects: 0,
        timeout: 30_000,
      });
      if (response.status() >= 300 && response.status() < 400) {
        failures.push(`blocked authenticated redirect: ${response.status()}`);
        await route.abort('blockedbyclient');
        return;
      }
      await route.fulfill({ response });
    } catch (error) {
      failures.push(`authenticated origin proxy failed: ${error.message}`);
      await route.abort('failed');
    } finally {
      await response?.dispose();
    }
  });
}
