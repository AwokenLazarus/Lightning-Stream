import { setupManifest } from '@start9labs/start-sdk'
import { long, short } from './i18n'
import { IMAGES } from '../spec'

// The images are the published ones the spec pins by digest (packaging/images.lock: the image set of the
// Umbrel app, the Linux package and xbt-compute); `start-cli s9pk pack` takes each architecture from the
// local Docker, so a .s9pk carries them. StartOS runs x86_64 and aarch64 (the images also exist for arm/v7).

export const manifest = setupManifest({
  id: 'lightning-stream',
  title: 'Lightning Stream',
  license: 'MIT OR Apache-2.0',
  packageRepo: 'https://github.com/AwokenLazarus/Lightning-Stream',
  upstreamRepo: 'https://github.com/AwokenLazarus/Lightning-Stream',
  marketingUrl: 'https://github.com/AwokenLazarus/Lightning-Stream',
  donationUrl: null,
  description: { short, long },
  volumes: ['main', 'startos'],
  images: {
    init: { source: { dockerTag: IMAGES.init }, arch: ['x86_64', 'aarch64'] },
    signer: { source: { dockerTag: IMAGES.signer }, arch: ['x86_64', 'aarch64'] },
    witness: { source: { dockerTag: IMAGES.witness }, arch: ['x86_64', 'aarch64'] },
    mcp: { source: { dockerTag: IMAGES.mcp }, arch: ['x86_64', 'aarch64'] },
    ui: { source: { dockerTag: IMAGES.ui }, arch: ['x86_64', 'aarch64'] },
    gateway: { source: { dockerTag: IMAGES.gateway }, arch: ['x86_64', 'aarch64'] },
    connector: { source: { dockerTag: IMAGES.connector }, arch: ['x86_64', 'aarch64'] },
    hashlink: { source: { dockerTag: IMAGES.hashlink }, arch: ['x86_64', 'aarch64'] },
  },
  hardwareRequirements: {
    ram: 512 * 1024 ** 2, // 512 MiB: every service is a small static binary
  },
  dependencies: {
    'lightning-fork': {
      description: 'The Lightning node the app pays through and sells on. The app asks it for its own narrow keys (or you paste keys you make in it); only the one-shot that makes them reads the node, and no other service mounts its data.',
      optional: false,
      metadata: {
        title: 'Lightning Fork',
        icon: 'https://raw.githubusercontent.com/paulscode/lightning-fork-startos/master/icon.png',
      },
    },
  },
})
