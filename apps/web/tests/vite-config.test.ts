import { describe, it, expect } from 'vitest';
import viteConfig from '../vite.config.js';

describe('Vite Development Origin & Proxy Configuration', () => {
  it('standardizes local dev hostname on 127.0.0.1:5173 and proxies /api same-origin to Express 127.0.0.1:3000', () => {
    expect(viteConfig.server?.host).toBe('127.0.0.1');
    expect(viteConfig.server?.port).toBe(5173);
    expect(viteConfig.server?.strictPort).toBe(true);

    const apiProxy = viteConfig.server?.proxy?.['/api'];
    expect(apiProxy).toBeDefined();
    expect(typeof apiProxy).toBe('object');
    if (apiProxy && typeof apiProxy === 'object' && 'target' in apiProxy) {
      expect(apiProxy.target).toBe('http://127.0.0.1:3000');
      expect(apiProxy.changeOrigin).toBe(false);
    }
  });
});
