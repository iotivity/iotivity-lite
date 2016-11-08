Name: iotivity-constrained
Version: 0
Release: 0
Summary: Implementation of OCF for constrainted devices
Source: %{name}-%{version}.tar.gz
License: Apache-2.0
Group: Contrib

%if ! %{?license:0}
%define license %doc
%endif

BuildRequires: make

%description
IoTivity-Constrained is an open-source software stack and library that
implements the Open Connectivity Foundation (OCF) standards for the
Internet of Things (IoT).

It was designed to build IoT applications for resource-constrained
hardware and software environments. It targets the wide array of
embedded devices using low-power and low-cost MCUs that will proliferate the
IoT landscape.
%define MAKEFLAGS \\\
%{?_smp_mflags} \\\
libdir=%{_libdir} \\\
prefix=%{_prefix} \\\
%{?EXTRA_RPM_MAKEFLAGS}


%prep

%setup -q -n %{name}-%{version}

%build
MAKEFLAGS="%{MAKEFLAGS}" ; export MAKEFLAGS;
%__make

%install
MAKEFLAGS="%{MAKEFLAGS}" ; export MAKEFLAGS;
%make_install

%clean

%files
%license LICENSE.md
%{_libdir}/*
%{_includedir}/*

