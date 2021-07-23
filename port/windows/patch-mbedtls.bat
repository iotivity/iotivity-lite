@rem This batch file uses Git to apply the mbedTLS patches
@rem on Windows. Please adapt GIT_CMD below as required.
@rem Also adapt PATCH_CMD with the location of the patch
@rem utility, if automatic resolution does not work.

@rem If git.exe is not in PATH, then set the full path.
set GIT_CMD=git

@rem Get location of Git. ~p drops the executable name and keeps
@rem drive letter and path only. The output path has a trailing \.
for /f "tokens=*" %%i in ('where %GIT_CMD%') do set GIT_INSTALL_DIR=%%~dpi

@rem Now iterate up to find the Git top-level directory.
:redo
@rem Drop the trailing slash
set GIT_INSTALL_DIR=%GIT_INSTALL_DIR:~0,-1%
@rem Get parent directory
for /f "tokens=*" %%i in ("%GIT_INSTALL_DIR%") do set GIT_INSTALL_DIR=%%~dpi
@rem Get the directory name (last folder)
for /f "tokens=*" %%i in ("%GIT_INSTALL_DIR:~0,-1%") do set LAST_DIR=%%~ni
if "%LAST_DIR%" == "" goto error
if NOT %LAST_DIR% == Git goto redo

@rem Now search for the patch tool starting from the Git top-level directory
for /f "tokens=*" %%i in ('where /R "%GIT_INSTALL_DIR:~0,-1%" patch.exe') do set PATCH_CMD=%%~fi

@rem current working directory for recovery
set OLD_CWD=%CD%

if exist "%~dp0..\..\deps\mbedtls\" (
	cd "%~dp0..\..\deps\mbedtls" || goto error
	"%GIT_CMD%" clean -xdf .  || goto error
	"%GIT_CMD%" reset --hard  || goto error
	cd "%OLD_CWD%" || goto error
)

"%GIT_CMD%" submodule update --init

cd %~dp0..\..\deps\mbedtls || goto error
@rem git apply cannot deal with "/dev/null" as input to create a new
@rem file. Hence, we are using its patch utility directly.
@rem -r -: do not create reject files if applying hunks fail
@rem -s  : work silently
@rem -N  : do not reverse the patch if already applied
@rem -p1 : remove first path component from paths in the patches
for /r ..\..\patches %%F IN (05_mbedtls_ocf-microsoft.patch 06_mbedtls_constrained.patch 08_mbedtls_C99.patch 09-ocf-samsung-psk.patch 10-ocf-samsung-anon.patch) DO (
  "%PATCH_CMD%" -r - -s -N -p1 < %%F || goto error
)
@rem VS project can check existence of the file whether to invoke
@rem this batch file or not.
echo patches applied > patched.txt
cd "%OLD_CWD%"
exit /b 0

:error
cd "%OLD_CWD%"
exit /b 1
