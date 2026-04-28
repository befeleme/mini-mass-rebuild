#!/usr/bin/python3
"""
Optimized version using the Copr Python API.
Key optimization: Get ALL builds in ONE API call instead of 4000+ subprocess calls.
"""
import asyncio
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

import rpm
from copr.v3 import Client

BATCH_SIZE = 1000

copr_arg = sys.argv[1]
ownername, projectname = copr_arg.split('/')


def drop_dist(version):
    *_, release = parse_evr(version)
    if '.fc' in release:
        return '.'.join(version.split('.')[:-1])
    return version


def parse_evr(evr):
    e, _, vr = evr.rpartition(':')
    if e == '':
        e = None
    v, _, r = vr.rpartition('-')
    return e, v, r


def fetch_all_builds(client):
    """
    Fetch ALL succeeded builds for the project in one API call.
    This is the KEY optimization - replaces 4000+ subprocess calls with 1 API call.
    """
    print(f'Fetching all succeeded builds from {copr_arg}...')
    builds = client.build_proxy.get_list(
        ownername=ownername,
        projectname=projectname,
        status='succeeded'
    )
    # Convert generator to list to see progress
    builds_list = list(builds)
    print(f'Retrieved {len(builds_list)} succeeded builds')
    return builds_list


def group_builds_by_package(builds, filter_packages=None):
    """Group builds by package name."""
    packages = defaultdict(list)

    for build in builds:
        # Only process builds from this specific project
        if build['project_dirname'] != projectname:
            continue

        pkg_name = build['source_package']['name']

        # Filter if specific packages requested
        if filter_packages and pkg_name not in filter_packages:
            continue

        packages[pkg_name].append(build)

    return packages


def process_package_builds(pkg_name, builds):
    """
    Process builds for a single package and return build IDs to delete.
    Returns: (pkg_name, set of build IDs to delete)
    """
    if len(builds) <= 1:
        return pkg_name, set()

    # Build version map
    versions = {}
    for build in builds:
        versions[build['id']] = drop_dist(build['source_package']['version'])

    # Find newest build
    newest = max(versions.keys())
    newest_version = versions[newest]
    print(f'Newest {pkg_name} build is {newest}, {newest_version}')
    del versions[newest]

    # Mark older/equal versions for deletion
    to_delete = set()
    for buildid, version in versions.items():
        e = rpm.labelCompare(parse_evr(newest_version), parse_evr(version))
        if e in [0, -1]:  # newest >= version (keep newest)
            to_delete.add(buildid)
            print(f'Will delete {buildid}, {pkg_name} {version}')

    if to_delete:
        print()

    return pkg_name, to_delete


def delete_builds_sync(client, build_ids):
    """Delete builds synchronously."""
    print(f'Deleting {len(build_ids)} builds...')

    # Use delete_list if available and efficient, otherwise delete one by one
    for build_id in build_ids:
        try:
            client.build_proxy.delete(build_id)
            print(f'Deleted build {build_id}')
        except Exception as e:
            print(f'Failed to delete build {build_id}: {e}')


async def main():
    # Initialize copr client
    client = Client.create_from_config_file()

    # Get ALL builds in ONE API call (major optimization!)
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=1) as pool:
        all_builds = await loop.run_in_executor(pool, fetch_all_builds, client)

    # Filter packages if specified
    filter_packages = set(sys.argv[2:]) if sys.argv[2:] else None

    # Group builds by package
    packages = group_builds_by_package(all_builds, filter_packages)
    print(f'Found {len(packages)} packages with builds')

    if filter_packages:
        print(f'Processing {len(packages)} filtered packages')

    # Process each package's builds in parallel (CPU-bound work)
    to_delete_all = set()

    with ThreadPoolExecutor(max_workers=20) as pool:
        tasks = []
        for pkg_name, builds in packages.items():
            print(f'Checking {pkg_name} ({len(builds)} builds)')
            task = loop.run_in_executor(
                pool,
                process_package_builds,
                pkg_name,
                builds
            )
            tasks.append(task)

        # Wait for all processing to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect all builds to delete
        for result in results:
            if isinstance(result, Exception):
                print(f'Error processing package: {result}')
            else:
                pkg_name, to_delete = result
                to_delete_all.update(to_delete)

    # Delete builds if any
    if to_delete_all:
        print(f'\nTotal builds to delete: {len(to_delete_all)}')
        with ThreadPoolExecutor(max_workers=1) as pool:
            await loop.run_in_executor(
                pool,
                delete_builds_sync,
                client,
                sorted(to_delete_all)
            )
    else:
        print('\nNo builds to delete')


if __name__ == '__main__':
    asyncio.run(main())
