/**
 * Route chunk preloaders.
 *
 * Each entry is a dynamic import that points at the SAME module path used in
 * App.tsx's `React.lazy(() => import(...))` call. Vite assigns each module a
 * stable chunk identity by path, so calling these preloaders kicks the chunk
 * fetch and parse early — the lazy() in App.tsx then resolves instantly when
 * the user actually navigates.
 *
 * Wire-up: attach `onMouseEnter` + `onFocus` handlers on internal nav links
 * (AppShell, in-app nav menus) that look up the preloader by path and call
 * it. Repeated calls are cheap — the module is cached after first load.
 */

type Preloader = () => Promise<unknown>;

export const routePreloaders: Record<string, Preloader> = {
  // DFIR app nav
  '/dfir': () => import('../pages/dfir/Dashboard'),
  '/dfir/ioc-check': () => import('../pages/dfir/IocCheck'),
  '/dfir/url-preview': () => import('../pages/dfir/UrlPreview'),
  '/dfir/domain': () => import('../pages/dfir/Domain'),
  '/dfir/cve': () => import('../pages/dfir/Cve'),
  '/dfir/diamond': () => import('../pages/dfir/Diamond'),
  '/dfir/threat-map': () => {
    // Threat-map's bottleneck is the 190KB world-110m.json topojson on top of
    // the react-simple-maps chunk. Warm both concurrently so the first render
    // doesn't sit on a sequential 250-400ms wait.
    void fetch('/world-110m.json', { credentials: 'omit' }).catch(() => {});
    return import('../pages/dfir/ThreatMap');
  },
};

/**
 * Preload a route's chunk. No-op if the path isn't mapped or already loaded.
 */
export function preloadRoute(path: string): void {
  const fn = routePreloaders[path];
  if (fn) void fn().catch(() => {});
}
