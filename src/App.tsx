import { useEffect, Suspense, lazy } from 'react';
import { BrowserRouter, Routes, Route, useLocation, useSearchParams, Navigate } from 'react-router-dom';
import { useTheme } from './hooks';
import { SkipToContent } from './components/SkipToContent';
import { StructuredData } from './components/StructuredData';
import { AppShell } from './components/AppShell';
import { BackgroundLayer } from './components/BackgroundLayer';
import { CommandPalette } from './components/dfir/CommandPalette';
import { ErrorBoundary } from './components/ErrorBoundary';

// Lazy-loaded DFIR pages. Initial paint only ships JS for the current
// route; everything else is fetched on demand. This file routes /dfir/*
// only — there is no portfolio chrome and no /threatintel surface in
// this app.
const DFIR = lazy(() => import('./pages/dfir/Dashboard'));
const IocCheck = lazy(() => import('./pages/dfir/IocCheck'));
const Phishing = lazy(() => import('./pages/dfir/Phishing'));
const Domain = lazy(() => import('./pages/dfir/Domain'));
const FullSpectrum = lazy(() => import('./pages/dfir/FullSpectrum'));
const Exposure = lazy(() => import('./pages/dfir/Exposure'));
const Wiki = lazy(() => import('./pages/dfir/Wiki'));
const WikiArticle = lazy(() => import('./pages/dfir/WikiArticle'));
const Dashboard = lazy(() => import('./pages/dfir/Dashboard'));
const Actors = lazy(() => import('./pages/dfir/Actors'));
const ActorDetail = lazy(() => import('./pages/dfir/ActorDetail'));
const Privacy = lazy(() => import('./pages/dfir/Privacy'));
const Briefings = lazy(() => import('./pages/dfir/Briefings'));
const BriefingDetail = lazy(() => import('./pages/dfir/BriefingDetail'));
const Cve = lazy(() => import('./pages/dfir/Cve'));
const Decode = lazy(() => import('./pages/dfir/Decode'));
const Encoder = lazy(() => import('./pages/dfir/Encoder'));
const CertSearch = lazy(() => import('./pages/dfir/CertSearch'));
const AsnLookup = lazy(() => import('./pages/dfir/AsnLookup'));
const Breach = lazy(() => import('./pages/dfir/Breach'));
const ExifParse = lazy(() => import('./pages/dfir/ExifParse'));
const MitreMatrix = lazy(() => import('./pages/dfir/MitreMatrix'));
const AtlasMatrix = lazy(() => import('./pages/dfir/AtlasMatrix'));
const UrlPreview = lazy(() => import('./pages/dfir/UrlPreview'));
const IocExtractor = lazy(() => import('./pages/dfir/IocExtractor'));
const IocPivot = lazy(() => import('./pages/dfir/IocPivot'));
const JwtInspect = lazy(() => import('./pages/dfir/JwtInspect'));
const GoogleDorks = lazy(() => import('./pages/dfir/GoogleDorks'));
const IamPolicyAnalyzer = lazy(() => import('./pages/dfir/IamPolicyAnalyzer'));
const SecurityGroupAnalyzer = lazy(() => import('./pages/dfir/SecurityGroupAnalyzer'));
const CloudTrailTriage = lazy(() => import('./pages/dfir/CloudTrailTriage'));
const K8sRbacAnalyzer = lazy(() => import('./pages/dfir/K8sRbacAnalyzer'));
const CvePrioritizer = lazy(() => import('./pages/dfir/CvePrioritizer'));
const RuleConverter = lazy(() => import('./pages/dfir/RuleConverter'));
const LinuxTriage = lazy(() => import('./pages/dfir/LinuxTriage'));
const TerraformScanner = lazy(() => import('./pages/dfir/TerraformScanner'));
const GcpIamAnalyzer = lazy(() => import('./pages/dfir/GcpIamAnalyzer'));
const AzureRbacAnalyzer = lazy(() => import('./pages/dfir/AzureRbacAnalyzer'));
const OpenApiAuditor = lazy(() => import('./pages/dfir/OpenApiAuditor'));
const SecHeadersAnalyzer = lazy(() => import('./pages/dfir/SecHeadersAnalyzer'));
const SecretScanner = lazy(() => import('./pages/dfir/SecretScanner'));
const GraphqlAuditor = lazy(() => import('./pages/dfir/GraphqlAuditor'));
const OsvScanner = lazy(() => import('./pages/dfir/OsvScanner'));
const Punycode = lazy(() => import('./pages/dfir/Punycode'));
const Takeover = lazy(() => import('./pages/dfir/Takeover'));
const StixViewer = lazy(() => import('./pages/dfir/StixViewer'));
const StixBuilder = lazy(() => import('./pages/dfir/StixBuilder'));
const DarkWeb = lazy(() => import('./pages/dfir/DarkWeb'));
const ThreatMap = lazy(() => import('./pages/dfir/ThreatMap'));
const Rules = lazy(() => import('./pages/dfir/Rules'));
const Owasp = lazy(() => import('./pages/dfir/Owasp'));
const PromptInjection = lazy(() => import('./pages/dfir/PromptInjection'));
const McpAudit = lazy(() => import('./pages/dfir/McpAudit'));
const KillChain = lazy(() => import('./pages/dfir/KillChain'));
const Diamond = lazy(() => import('./pages/dfir/Diamond'));
const Lolbins = lazy(() => import('./pages/dfir/Lolbins'));
const RulePlayground = lazy(() => import('./pages/dfir/RulePlayground'));
const YaraManager = lazy(() => import('./pages/dfir/YaraManager'));
const DetectionLab = lazy(() => import('./pages/dfir/DetectionLab'));
const EmailDefense = lazy(() => import('./pages/dfir/EmailDefense'));
const Nhi = lazy(() => import('./pages/dfir/Nhi'));
const PowershellDeobf = lazy(() => import('./pages/dfir/PowershellDeobf'));
const AgentMap = lazy(() => import('./pages/dfir/AgentMap'));
const Tabletop = lazy(() => import('./pages/dfir/Tabletop'));
const Grc = lazy(() => import('./pages/dfir/Grc'));
const DlpScan = lazy(() => import('./pages/dfir/DlpScan'));
const DataClassification = lazy(() => import('./pages/dfir/DataClassification'));
const PrivacyHub = lazy(() => import('./pages/dfir/PrivacyHub'));
const UsernamePivot = lazy(() => import('./pages/dfir/UsernamePivot'));
const Wayback = lazy(() => import('./pages/dfir/Wayback'));
const IpGeo = lazy(() => import('./pages/dfir/IpGeo'));
const LogParser = lazy(() => import('./pages/dfir/LogParser'));
const Socmint = lazy(() => import('./pages/dfir/Socmint'));
const OsintFramework = lazy(() => import('./pages/dfir/OsintFramework'));
const SecopsCatalog = lazy(() => import('./pages/dfir/SecopsCatalog'));
const ToolsCategory = lazy(() => import('./pages/dfir/ToolsCategory'));
const ToolsAbout = lazy(() => import('./pages/dfir/ToolsAbout'));
const TimestampConverter = lazy(() => import('./pages/dfir/TimestampConverter'));
const HashCalculator = lazy(() => import('./pages/dfir/HashCalculator'));
const DorkBuilder = lazy(() => import('./pages/dfir/DorkBuilder'));
const BrandImpersonation = lazy(() => import('./pages/dfir/BrandImpersonation'));
const ImageFingerprint = lazy(() => import('./pages/dfir/ImageFingerprint'));
const PlistProtobuf = lazy(() => import('./pages/dfir/PlistProtobuf'));
const PcapTriage = lazy(() => import('./pages/dfir/PcapTriage'));
const RegistryHive = lazy(() => import('./pages/dfir/RegistryHive'));
const EvtxParser = lazy(() => import('./pages/dfir/EvtxParser'));
const SqliteExplorer = lazy(() => import('./pages/dfir/SqliteExplorer'));
const IosBackupExplorer = lazy(() => import('./pages/dfir/IosBackupExplorer'));
const ScreenshotIntel = lazy(() => import('./pages/dfir/ScreenshotIntel'));
const PeAnalyzer = lazy(() => import('./pages/dfir/PeAnalyzer'));
const WebLogAnalyzer = lazy(() => import('./pages/dfir/WebLogAnalyzer'));
const PrefetchAnalyzer = lazy(() => import('./pages/dfir/PrefetchAnalyzer'));
const CveResourcesCatalog = lazy(() => import('./pages/dfir/CveResourcesCatalog'));
const WebScan = lazy(() => import('./pages/dfir/WebScan'));
const MalwareScan = lazy(() => import('./pages/dfir/MalwareScan'));
const ReverseImage = lazy(() => import('./pages/dfir/ReverseImage'));
const EmlExtractor = lazy(() => import('./pages/dfir/EmlExtractor'));
const ScamWatch = lazy(() => import('./pages/dfir/ScamWatch'));
const CryptoTrace = lazy(() => import('./pages/dfir/CryptoTrace'));
const TechAiNews = lazy(() => import('./pages/dfir/TechAiNews'));
const ThreatFeeds = lazy(() => import('./pages/dfir/ThreatFeeds'));
const OnionWatch = lazy(() => import('./pages/dfir/OnionWatch'));
const TelegramWatch = lazy(() => import('./pages/dfir/TelegramWatch'));
const AwesomeLists = lazy(() => import('./pages/dfir/AwesomeLists'));
const UrlReputation = lazy(() => import('./pages/dfir/UrlReputation'));
const DomainReputation = lazy(() => import('./pages/dfir/DomainReputation'));
const ApkAnalyzer = lazy(() => import('./pages/dfir/ApkAnalyzer'));
const EmailReputation = lazy(() => import('./pages/dfir/EmailReputation'));
const DmarcAnalyzer = lazy(() => import('./pages/dfir/DmarcAnalyzer'));

/**
 * /dfir/file?h=<hash> is the legacy entry point for the standalone hash
 * analyser. The page was merged into the IOC checker; this redirect rewrites
 * `?h=<hash>` to `?indicator=<hash>` so legacy bookmarks auto-populate the
 * input rather than landing on a blank form.
 */
function DfirFileRedirect() {
  const [params] = useSearchParams();
  const hash = params.get('h');
  const target = hash ? `/dfir/ioc-check?indicator=${encodeURIComponent(hash)}` : '/dfir/ioc-check';
  return <Navigate to={target} replace />;
}

function SectionLoader() {
  return (
    <div className="min-h-[200px] flex items-center justify-center" aria-hidden="true">
      <div className="w-8 h-8 border-2 border-brand-200 border-t-brand-600 rounded-full animate-spin" />
    </div>
  );
}

// Wrapper to reduce JSX noise for the dozens of route definitions.
function R({ Component }: { Component: React.ComponentType }) {
  return (
    <ErrorBoundary>
      <Suspense fallback={<SectionLoader />}>
        <Component />
      </Suspense>
    </ErrorBoundary>
  );
}

export function AppContent() {
  const { isDark, toggleTheme } = useTheme();
  const location = useLocation();

  useEffect(() => {
    if (location.hash) {
      const id = location.hash.substring(1);
      const element = document.getElementById(id);
      if (element) {
        element.scrollIntoView({ behavior: 'smooth' });
      }
    } else {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  }, [location.hash]);

  const routes = (
    <Routes>
      {/* Root → DFIR dashboard. */}
      <Route path="/" element={<Navigate to="/dfir" replace />} />
      <Route path="/dfir" element={<R Component={DFIR} />} />
      <Route path="/dfir/ioc-check" element={<R Component={IocCheck} />} />
      <Route path="/dfir/phishing" element={<R Component={Phishing} />} />
      <Route path="/dfir/domain" element={<R Component={Domain} />} />
      <Route path="/dfir/domain-rep" element={<R Component={DomainReputation} />} />
      <Route path="/dfir/full-spectrum" element={<R Component={FullSpectrum} />} />
      <Route path="/dfir/exposure" element={<R Component={Exposure} />} />
      <Route path="/dfir/file" element={<DfirFileRedirect />} />
      <Route path="/dfir/wiki" element={<R Component={Wiki} />} />
      <Route path="/dfir/wiki/:slug" element={<R Component={WikiArticle} />} />
      <Route path="/dfir/dashboard" element={<R Component={Dashboard} />} />
      <Route path="/dfir/actors" element={<R Component={Actors} />} />
      <Route path="/dfir/actors/:slug" element={<R Component={ActorDetail} />} />
      <Route path="/dfir/privacy" element={<R Component={Privacy} />} />
      <Route path="/dfir/briefings" element={<R Component={Briefings} />} />
      <Route path="/dfir/briefings/:slug" element={<R Component={BriefingDetail} />} />
      <Route path="/dfir/cve" element={<R Component={Cve} />} />
      <Route path="/dfir/decode" element={<R Component={Decode} />} />
      <Route path="/dfir/encoder" element={<R Component={Encoder} />} />
      <Route path="/dfir/cert-search" element={<R Component={CertSearch} />} />
      <Route path="/dfir/atlas" element={<R Component={AtlasMatrix} />} />
      <Route path="/dfir/mitre" element={<R Component={MitreMatrix} />} />
      <Route path="/dfir/asn" element={<R Component={AsnLookup} />} />
      <Route path="/dfir/breach" element={<R Component={Breach} />} />
      <Route path="/dfir/exif" element={<R Component={ExifParse} />} />
      <Route path="/dfir/url-preview" element={<R Component={UrlPreview} />} />
      <Route path="/dfir/extract" element={<R Component={IocExtractor} />} />
      <Route path="/dfir/ioc-pivot" element={<R Component={IocPivot} />} />
      <Route path="/dfir/jwt" element={<R Component={JwtInspect} />} />
      <Route path="/dfir/google-dorks" element={<R Component={GoogleDorks} />} />
      <Route path="/dfir/iam-analyzer" element={<R Component={IamPolicyAnalyzer} />} />
      <Route path="/dfir/sg-analyzer" element={<R Component={SecurityGroupAnalyzer} />} />
      <Route path="/dfir/cloudtrail-triage" element={<R Component={CloudTrailTriage} />} />
      <Route path="/dfir/k8s-rbac" element={<R Component={K8sRbacAnalyzer} />} />
      <Route path="/dfir/cve-prioritizer" element={<R Component={CvePrioritizer} />} />
      <Route path="/dfir/sigma-convert" element={<Navigate to="/dfir/rule-converter" replace />} />
      <Route path="/dfir/rule-converter" element={<R Component={RuleConverter} />} />
      <Route path="/dfir/linux-triage" element={<R Component={LinuxTriage} />} />
      <Route path="/dfir/terraform-scan" element={<R Component={TerraformScanner} />} />
      <Route path="/dfir/gcp-iam" element={<R Component={GcpIamAnalyzer} />} />
      <Route path="/dfir/azure-rbac" element={<R Component={AzureRbacAnalyzer} />} />
      <Route path="/dfir/openapi-audit" element={<R Component={OpenApiAuditor} />} />
      <Route path="/dfir/sec-headers" element={<R Component={SecHeadersAnalyzer} />} />
      <Route path="/dfir/secret-scan" element={<R Component={SecretScanner} />} />
      <Route path="/dfir/graphql-audit" element={<R Component={GraphqlAuditor} />} />
      <Route path="/dfir/osv-scan" element={<R Component={OsvScanner} />} />
      <Route path="/dfir/punycode" element={<R Component={Punycode} />} />
      <Route path="/dfir/takeover" element={<R Component={Takeover} />} />
      <Route path="/dfir/stix" element={<R Component={StixViewer} />} />
      <Route path="/dfir/stix-builder" element={<R Component={StixBuilder} />} />
      <Route path="/dfir/stix-builder/b/:bundleId" element={<R Component={StixBuilder} />} />
      <Route path="/dfir/darkweb" element={<R Component={DarkWeb} />} />
      <Route path="/dfir/threat-map" element={<R Component={ThreatMap} />} />
      <Route path="/dfir/rules" element={<R Component={Rules} />} />
      <Route path="/dfir/owasp" element={<R Component={Owasp} />} />
      <Route path="/dfir/prompt-injection" element={<R Component={PromptInjection} />} />
      <Route path="/dfir/mcp-audit" element={<R Component={McpAudit} />} />
      <Route path="/dfir/kill-chain" element={<R Component={KillChain} />} />
      <Route path="/dfir/diamond" element={<R Component={Diamond} />} />
      <Route path="/dfir/lolbins" element={<R Component={Lolbins} />} />
      <Route path="/dfir/rule-playground" element={<R Component={RulePlayground} />} />
      <Route path="/dfir/yara" element={<R Component={YaraManager} />} />
      <Route path="/dfir/detection-lab" element={<R Component={DetectionLab} />} />
      <Route path="/dfir/email-defense" element={<R Component={EmailDefense} />} />
      <Route path="/dfir/dmarc-analyzer" element={<R Component={DmarcAnalyzer} />} />
      <Route path="/dfir/nhi" element={<R Component={Nhi} />} />
      <Route path="/dfir/powershell-deobf" element={<R Component={PowershellDeobf} />} />
      <Route path="/dfir/agent-map" element={<R Component={AgentMap} />} />
      <Route path="/dfir/tabletop" element={<R Component={Tabletop} />} />
      <Route path="/dfir/grc" element={<R Component={Grc} />} />
      <Route path="/dfir/dlp-scan" element={<R Component={DlpScan} />} />
      <Route path="/dfir/data-classification" element={<R Component={DataClassification} />} />
      <Route path="/dfir/privacy-hub" element={<R Component={PrivacyHub} />} />
      <Route path="/dfir/username" element={<R Component={UsernamePivot} />} />
      <Route path="/dfir/wayback" element={<R Component={Wayback} />} />
      <Route path="/dfir/ip-geo" element={<R Component={IpGeo} />} />
      <Route path="/dfir/log-parser" element={<R Component={LogParser} />} />
      <Route path="/dfir/socmint" element={<R Component={Socmint} />} />
      <Route path="/dfir/osint-framework" element={<R Component={OsintFramework} />} />
      <Route path="/dfir/secops-tools" element={<R Component={SecopsCatalog} />} />
      <Route path="/dfir/tools/about" element={<R Component={ToolsAbout} />} />
      <Route path="/dfir/tools/:group" element={<R Component={ToolsCategory} />} />
      <Route path="/dfir/timestamp" element={<R Component={TimestampConverter} />} />
      <Route path="/dfir/hash-calc" element={<R Component={HashCalculator} />} />
      <Route path="/dfir/dork-builder" element={<R Component={DorkBuilder} />} />
      <Route path="/dfir/brand-impersonation" element={<R Component={BrandImpersonation} />} />
      <Route path="/dfir/image-fingerprint" element={<R Component={ImageFingerprint} />} />
      <Route path="/dfir/plist-protobuf" element={<R Component={PlistProtobuf} />} />
      <Route path="/dfir/pcap-triage" element={<R Component={PcapTriage} />} />
      <Route path="/dfir/registry-hive" element={<R Component={RegistryHive} />} />
      <Route path="/dfir/evtx" element={<R Component={EvtxParser} />} />
      <Route path="/dfir/sqlite" element={<R Component={SqliteExplorer} />} />
      <Route path="/dfir/mobile-sqlite" element={<R Component={SqliteExplorer} />} />
      <Route path="/dfir/ios-backup" element={<R Component={IosBackupExplorer} />} />
      <Route path="/dfir/screenshot-intel" element={<R Component={ScreenshotIntel} />} />
      <Route path="/dfir/apk-analyzer" element={<R Component={ApkAnalyzer} />} />
      <Route path="/dfir/pe" element={<R Component={PeAnalyzer} />} />
      <Route path="/dfir/web-log" element={<R Component={WebLogAnalyzer} />} />
      <Route path="/dfir/prefetch" element={<R Component={PrefetchAnalyzer} />} />
      <Route path="/dfir/cve-resources" element={<R Component={CveResourcesCatalog} />} />
      <Route path="/dfir/web-scan" element={<R Component={WebScan} />} />
      <Route path="/dfir/malware-scan" element={<R Component={MalwareScan} />} />
      <Route path="/dfir/reverse-image" element={<R Component={ReverseImage} />} />
      <Route path="/dfir/eml" element={<R Component={EmlExtractor} />} />
      <Route path="/dfir/url-rep" element={<R Component={UrlReputation} />} />
      <Route path="/dfir/email-rep" element={<R Component={EmailReputation} />} />
      <Route path="/dfir/scam-watch" element={<R Component={ScamWatch} />} />
      <Route path="/dfir/crypto-trace" element={<R Component={CryptoTrace} />} />
      <Route path="/dfir/tech-ai-news" element={<R Component={TechAiNews} />} />
      <Route path="/dfir/threat-feeds" element={<R Component={ThreatFeeds} />} />
      <Route path="/dfir/onion-watch" element={<R Component={OnionWatch} />} />
      <Route path="/dfir/telegram-watch" element={<R Component={TelegramWatch} />} />
      <Route path="/dfir/awesome-lists" element={<R Component={AwesomeLists} />} />
      <Route path="/difr" element={<Navigate to="/dfir" replace />} />
      <Route path="/dfir/discord-watch" element={<Navigate to="/dfir/awesome-lists" replace />} />
      {/* Catch-all → DFIR home. */}
      <Route path="*" element={<Navigate to="/dfir" replace />} />
    </Routes>
  );

  return (
    <>
      <StructuredData />
      <SkipToContent />
      <BackgroundLayer isDark={isDark} />
      <CommandPalette />
      <AppShell mode="dfir" isDark={isDark} onToggleTheme={toggleTheme}>
        {routes}
      </AppShell>
      <div id="aria-live-region" aria-live="polite" aria-atomic="true" className="sr-only" />
    </>
  );
}

function App() {
  return (
    <BrowserRouter>
      <AppContent />
    </BrowserRouter>
  );
}

export default App;
