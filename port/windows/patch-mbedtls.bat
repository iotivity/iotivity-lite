@rem This batch file uses Git to apply the mbedTLS patches
@rem on Windows. Please adapt GIT_CMD below as required.
@rem Also adapt PATCH_CMD with the location of the patch
@rem utility, if automatic resolution does not work.

@rem If git.exe is not in PATH, then set the full path.
set GIT_CMD=git

@rem Get location of Git. ~p drops the executable name and keeps
@rem the path only
for /f "tokens=*" %%i in ('where %GIT_CMD%') do set GIT_LOCATION=%%~pi
set PATCH_CMD=%GIT_LOCATION%..\usr\bin\patch.exe

"%GIT_CMD%" submodule update --init

cd %~dp0..\..\deps\mbedtls || goto error
"%GIT_CMD%" clean -xdf .  || goto error
"%GIT_CMD%" reset --hard  || goto error
@rem git apply cannot deal with "/dev/null" as input to create a new
@rem file. Hence, we are using its patch utility directly.
@rem -r -: do not create reject files if applying hunks fail
@rem -s  : work silently
@rem -N  : do not reverse the patch if already applied
@rem -p1 : remove first path component from paths in the patches
"%PATCH_CMD%" -r - -s -N -p1 < ..\..\patches\mbedtls_ocf_patch_1 || goto error
"%PATCH_CMD%" -r - -s -N -p1 < ..\..\patches\mbedtls_iotivity_constrained_patch_2 || goto error
@rem VS project can check existence of the file whether to invoke
@rem this batch file or not.
echo patches applied > patched.txt
exit /b 0

:error
exit /b 1

