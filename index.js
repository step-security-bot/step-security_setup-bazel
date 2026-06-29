import fs from 'fs'
import crypto from 'crypto'
import { setTimeout } from 'timers/promises'
import * as core from '@actions/core'
import * as cache from '@actions/cache'
import * as github from '@actions/github'
import * as glob from '@actions/glob'
import * as tc from '@actions/tool-cache'
import config from './config.js'
import axios from 'axios'

async function validateSubscription() {
  let repoPrivate;
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (eventPath && fs.existsSync(eventPath)) {
    const payload = JSON.parse(fs.readFileSync(eventPath, "utf8"));
    repoPrivate = payload?.repository?.private;
  }

  const upstream = 'bazel-contrib/setup-bazel';
  const action = process.env.GITHUB_ACTION_REPOSITORY;
  const docsUrl = 'https://docs.stepsecurity.io/actions/stepsecurity-maintained-actions';
  core.info('');
  core.info('\u001b[1;36mStepSecurity Maintained Action\u001b[0m');
  core.info(`Secure drop-in replacement for ${upstream}`);
  if (repoPrivate === false) core.info('\u001b[32m\u2713 Free for public repositories\u001b[0m');
  core.info(`\u001b[36mLearn more:\u001b[0m ${docsUrl}`);
  core.info('');
  if (repoPrivate === false) return;
  const serverUrl = process.env.GITHUB_SERVER_URL || 'https://github.com';
  const body = { action: action || '' };
  if (serverUrl !== 'https://github.com') body.ghes_server = serverUrl;
  try {
    await axios.post(
      `https://agent.api.stepsecurity.io/v1/github/${process.env.GITHUB_REPOSITORY}/actions/maintained-actions-subscription`,
      body, { timeout: 3000 }
    );
  } catch (error) {
    if (axios.isAxiosError(error) && error.response?.status === 403) {
      core.error(`\u001b[1;31mThis action requires a StepSecurity subscription for private repositories.\u001b[0m`);
      core.error(`\u001b[31mLearn how to enable a subscription: ${docsUrl}\u001b[0m`);
      process.exit(1);
    }
    core.info('Timeout or API not reachable. Continuing to next step.');
  }
}

async function run() {
  try {
    await validateSubscription()
    await setupBazel()
  } catch (error) {
    core.setFailed(error.stack)
  }
}

async function setupBazel() {
  core.startGroup('Configure Bazel')
  core.info('Configuration:')
  core.info(JSON.stringify(config, null, 2))

  await setupBazelrc()
  core.endGroup()

  await setupBazelisk()
  await restoreCache(config.bazeliskCache)
  await restoreCache(config.diskCache)
  await restoreCache(config.repositoryCache)
  await restoreExternalCaches(config.externalCache)
}

async function setupBazelisk() {
  if (config.bazeliskVersion.length == 0) {
    return
  }

  core.startGroup('Setup Bazelisk')
  let toolPath = tc.find('bazelisk', config.bazeliskVersion)
  if (toolPath) {
    core.debug(`Found in cache @ ${toolPath}`)
  } else {
    toolPath = await downloadBazelisk()
  }
  core.addPath(toolPath)
  core.endGroup()
}

async function verifyChecksum(filePath, expectedHash) {
  const fileContent = fs.readFileSync(filePath)
  const actualHash = crypto.createHash('sha256').update(fileContent).digest('hex')
  if (actualHash !== expectedHash) {
    core.warning(`Checksum mismatch for Bazelisk. Expected ${expectedHash}, got ${actualHash}`)
  } else {
    core.debug(`Checksum verified for Bazelisk`)
  }
}

async function downloadBazelisk() {
  const version = config.bazeliskVersion
  core.debug(`Attempting to download ${version}`)

  // Possible values are 'arm', 'arm64', 'ia32', 'mips', 'mipsel', 'ppc', 'ppc64', 's390', 's390x' and 'x64'.
  // Bazelisk filenames use 'amd64' and 'arm64'.
  let arch = config.os.arch
  if (arch == 'x64') {
    arch = 'amd64'
  }

  // Possible values are 'aix', 'darwin', 'freebsd', 'linux', 'openbsd', 'sunos' and 'win32'.
  // Bazelisk filenames use 'darwin', 'linux' and 'windows'.
  let platform = config.os.platform
  if (platform == "win32") {
    platform = "windows"
  }

  let filename = `bazelisk-${platform}-${arch}`
  if (platform == 'windows') {
    filename = `${filename}.exe`
  }

  const token = process.env.BAZELISK_GITHUB_TOKEN
  const octokit = github.getOctokit(token, {
    baseUrl: 'https://api.github.com'
  })
  const { data: releases } = await octokit.rest.repos.listReleases({
    owner: 'bazelbuild',
    repo: 'bazelisk'
  })

  // Find version matching semver specification.
  const tagName = tc.evaluateVersions(releases.map((r) => r.tag_name), version)
  const release = releases.find((r) => r.tag_name === tagName)
  if (!release) {
    throw new Error(`Unable to find Bazelisk version ${version}`)
  }

  const asset = release.assets.find((a) => a.name == filename)
  if (!asset) {
    throw new Error(`Unable to find Bazelisk version ${version} for platform ${platform}/${arch}`)
  }

  const checksumAsset = release.assets.find((a) => a.name == `${filename}.sha256`)
  if (!checksumAsset) {
    core.warning(`Checksum file not found for Bazelisk ${version}. Proceeding without verification.`)
  }

  const url = asset.browser_download_url
  core.debug(`Downloading from ${url}`)
  const downloadPath = await tc.downloadTool(url, undefined, `token ${token}`)

  if (checksumAsset) {
    const checksumUrl = checksumAsset.browser_download_url
    core.debug(`Downloading checksum from ${checksumUrl}`)
    const checksumPath = await tc.downloadTool(checksumUrl, undefined, `token ${token}`)
    const checksumContent = fs.readFileSync(checksumPath, 'utf8').trim()
    const expectedHash = checksumContent.split(' ')[0]
    await verifyChecksum(downloadPath, expectedHash)
    fs.unlinkSync(checksumPath)
  }

  core.debug('Adding to the cache...');
  fs.chmodSync(downloadPath, '755');
  let bazel_name = "bazel";
  if (platform == 'windows') {
    bazel_name = `${bazel_name}.exe`
  }
  const cachePath = await tc.cacheFile(downloadPath, bazel_name, 'bazelisk', version)
  core.debug(`Successfully cached bazelisk to ${cachePath}`)

  return cachePath
}

async function setupBazelrc() {
  for (const bazelrcPath of config.paths.bazelrc) {
    fs.writeFileSync(
      bazelrcPath,
      `startup --output_base=${config.paths.bazelOutputBase}\n`
    )
    fs.appendFileSync(bazelrcPath, config.bazelrc.join("\n"))
  }
}

async function restoreExternalCaches(cacheConfig) {
  if (!cacheConfig.enabled) {
    return
  }

  // First fetch the manifest of external caches used.
  const path = cacheConfig.manifest.path
  await restoreCache({
    enabled: true,
    files: cacheConfig.manifest.files,
    name: cacheConfig.manifest.name,
    paths: [path]
  })

  // Now restore all external caches defined in manifest
  if (fs.existsSync(path)) {
    const manifest = fs.readFileSync(path, { encoding: 'utf8' })
    const restorePromises = manifest.split('\n').filter(s => s)
      .map(name => {
        return restoreCache({
          enabled: cacheConfig[name]?.enabled ?? cacheConfig.default.enabled,
          files: cacheConfig[name]?.files || cacheConfig.default.files,
          name: cacheConfig.default.name(name),
          paths: cacheConfig.default.paths(name)
        });
      });
    await Promise.all(restorePromises);
  }
}

async function restoreCache(cacheConfig) {
  if (!cacheConfig.enabled) {
    return
  }

  const delay = Math.random() * 1000 // timeout <= 1 sec to reduce 429 errors
  await setTimeout(delay)

  core.startGroup(`Restore cache for ${cacheConfig.name}`)
  const name = cacheConfig.name
  try {
    const hash = await glob.hashFiles(cacheConfig.files.join('\n'))
    const paths = cacheConfig.paths
    const restoreKey = `${config.baseCacheKey}-${name}-`
    const key = `${restoreKey}${hash}`

    core.debug(`Attempting to restore ${name} cache from ${key}`)

    const restorePromise = cache.restoreCache(
      paths, key, [restoreKey],
      { segmentTimeoutInMs: 300000 } // 5 minutes per download segment
    )

    let restoredKey
    if (config.cacheRestoreTimeoutMs > 0) {
      const ac = new AbortController()
      const timeoutPromise = setTimeout(config.cacheRestoreTimeoutMs, null, { signal: ac.signal })
        .then(() => { throw new Error(`Timed out restoring ${name} cache after ${config.cacheRestoreTimeoutMs}ms`) })
      timeoutPromise.catch(() => {})

      try {
        restoredKey = await Promise.race([restorePromise, timeoutPromise])
      } finally {
        ac.abort()
      }
    } else {
      restoredKey = await restorePromise
    }

    if (restoredKey) {
      core.info(`Successfully restored cache from ${restoredKey}`)

      if (restoredKey === key) {
        core.saveState(`${name}-cache-hit`, 'true')
      }
    } else {
      core.info(`Failed to restore ${name} cache`)
    }
  } catch (err) {
    core.warning(`Failed to restore ${name} cache with error: ${err}`)
  } finally {
    core.endGroup()
  }
}

run()
