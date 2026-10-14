use std::path::Path;

/// A module filename is not an identity: old and hot-updated wrappers coexist.
pub(crate) fn same_module_path(candidate: &Path, target: &Path) -> bool {
    if candidate == target {
        return true;
    }
    match (candidate.canonicalize(), target.canonicalize()) {
        (Ok(candidate), Ok(target)) => candidate == target,
        _ => false,
    }
}

/// Keep the pathname intact, including spaces, after the five /proc/maps fields.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn maps_path(line: &str) -> Option<&str> {
    let mut rest = line;
    for _ in 0..5 {
        rest = rest.trim_start();
        let end = rest.find(char::is_whitespace)?;
        rest = &rest[end..];
    }
    let path = rest.trim_start();
    (!path.is_empty()).then_some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_versions_with_the_same_filename_are_not_the_same_module() {
        assert!(!same_module_path(
            Path::new("/synthetic/old/wrapper.node"),
            Path::new("/synthetic/hot/wrapper.node"),
        ));
        assert!(same_module_path(
            Path::new("/synthetic/hot/wrapper.node"),
            Path::new("/synthetic/hot/wrapper.node"),
        ));
        assert!(!same_module_path(
            Path::new("/synthetic/hot/notwrapper.node"),
            Path::new("/synthetic/hot/wrapper.node"),
        ));
    }

    #[test]
    fn maps_paths_preserve_spaces_and_exclude_another_versions_image() {
        let path = maps_path("1000-2000 r-xp 00000000 00:01 42     /synthetic/hot update/wrapper.node").unwrap();
        assert_eq!(path, "/synthetic/hot update/wrapper.node");
        assert!(!same_module_path(Path::new(path), Path::new("/synthetic/old/wrapper.node")));
        assert_eq!(maps_path("1000-2000 r-xp 00000000 00:01 42"), None);
    }

    #[test]
    fn deleted_maps_image_is_not_the_current_replacement_file() {
        assert!(!same_module_path(
            Path::new("/synthetic/hot/wrapper.node (deleted)"),
            Path::new("/synthetic/hot/wrapper.node"),
        ));
    }

    #[cfg(unix)]
    #[test]
    fn physical_path_aliases_match_without_using_the_filename() {
        let root = std::env::temp_dir().join(format!("nt-helper-module-identity-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
        let _cleanup = Cleanup(root.clone());
        let target = root.join("wrapper.node");
        let alias = root.join("alias.node");
        std::fs::write(&target, b"synthetic module").unwrap();
        std::os::unix::fs::symlink(&target, &alias).unwrap();
        assert!(same_module_path(&alias, &target));
    }
}
