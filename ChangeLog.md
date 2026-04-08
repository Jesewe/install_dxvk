## Summary

- Replace string comparison in detect_dxvk_version with VERSION_PRIORITY dict - 'd3d9' > 'd3d10' lexicographically, causing silent wrong DLL installs
- Add \_EXISTING_DETECTION_ORDER for get_existing_dxvk_version; superset DLL sets (d3d8, d3d10) must be checked before their subsets (d3d9, d3d11)
- Consolidate four separate DLL maps into a single DXVK_VERSION_MAP
- Replace exit(0) in class methods with InstallationCancelled exception; all process exits now live exclusively in main()
- Replace hand-rolled char loop in validate_dxvk_release with re.fullmatch
- Move check_for_update out of DXVKInstaller into dxvk_utils as a standalone function; eliminates the dummy-instance construction in main()
- Add \_HTTP_TIMEOUT = (5, 30) to all requests.get() calls
- Use pefile fast_load=True + targeted import-directory parse; add early exit once d3d11 (highest priority) is confirmed
- Create a single requests.Session in main(), passed to installer and check_for_update; adds User-Agent header for GitHub API courtesy
