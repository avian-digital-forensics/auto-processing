package utils

import "fmt"

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

	return fmt.Sprintf("%s\\%s", nuixPath, dirName)
}
