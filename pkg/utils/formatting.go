package utils

import (
	"path"
)

// RemoteScriptDir get the base-dirname of the avian-scripts path
func RemoteScriptDir(nuixPath, localScriptDir string) string {
	var dirName string
	for i := len(localScriptDir) - 1; i >= 0; i-- {
		if string(localScriptDir[i]) == "\\" {
			dirName = localScriptDir[i:]
			break
		}
		if string(localScriptDir[i]) == "/" {
			dirName = localScriptDir[i:]
			break
		}
	}

	return path.Join(nuixPath, dirName)
}

// Get the working directory available to the script.
func ScriptWorkDir(nuixPath string) string {
	return path.Join(nuixPath, "script_work_dir")
}
