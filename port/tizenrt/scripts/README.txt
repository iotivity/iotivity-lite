#############  TizenRT building steps ###################

1. Clone TizneRT from below mentioned link:
   https://github.com/Samsung/TizenRT/releases (download:  2.0_GBM_M1 stable release)

2. Create new directory with the name "iotivity-constrained" inside the external folder of TizneRT.
   $ cd external
   $ mkdir iotivity-constrained

3. Enter newly created "iotivity-constrained" directory.
   $ cd iotivity-constrained

4. Clone iotivity-constrained code from open source
   $ git clone --recursive https://gerrit.iotivity.org/gerrit/iotivity-constrained

5. Checkout to samsung branch.
   $ git branch -a
   $ git checkout remotes/origin/samsung

6. Run the Shell script from below mentioned directory path
   $ cd iotivity-constrained/port/tizenrt/scripts
   $ sh prep_build.sh

7. Enter the "os" directory of TizneRT and run the make.
   $ make
