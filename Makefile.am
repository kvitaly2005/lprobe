# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
# auto makefile for the lprobe
# (this file is processed with 'automake' to produce Makefile.in)
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#
#       Copyright (C) 2002-13 Luca Deri <deri@ltop.org> 
#
#                     http://www.ltop.org/ 
# 
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License along
#  with this program; if not, write to the Free Software Foundation, Inc.,
#  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#



AUTOMAKE_OPTIONS = 1.6   # Require Automake 1.6 or better.
ACLOCAL_AMFLAGS  = -I m4

#
## The name of the game with its own major, minor and release version.
VERSION  = @PACKAGE_VERSION@
PROGRAM  = @PACKAGE_NAME@

PLATFORM =`uname -p`

APPL= lprobe
REVISION=`svn info . | grep "^Revision"|cut -d " " -f 2`
PACKAGE=$(APPL)-@PACKAGE_VERSION@-$(REVISION).$(PLATFORM).rpm
PKGNAME  = @PACKAGE_NAME@

DEFS      = @DEFS@
INCS      = @INCS@

INCLUDES  = -I. $(INCS) -I @NDPI_INC@
LIBS      = @LIBS@ @CORELIBS@ @MORELIBS@ @NDPI_LIB@ @NT_LIB@
CC        = @CC@
CCLD      = @CCLD@
AM_CFLAGS = @CFLAGS@
AM_LDFLAGS= @LDFLAGS@

DISTCLEANFILES =  *~ *.log *.lo *.so *.o $(APPL) @PLUGINS@/*.o @PLUGINS@/*.lo  @PLUGINS@/*~ @PLUGINS@/*.so @PLUGINS@/*.la ./private/dmidecode-2.9/*.[oa~] .libs @PLUGINS@/.libs @USE_LICENSE@ lprobes
CLEANFILES     = $(DISTCLEANFILES)

SUBDIRS = . @PLUGINS@

PKG=lprobe-$(PACKAGE_VERSION)-$(REVISION).$(PLATFORM).rpm
N2DISK_PKG=n2disk-$(N2DISK_PACKAGE_VERSION)-$(REVISION).$(PLATFORM).rpm
N2DISKNT_PKG=n2disknt-$(N2DISK_PACKAGE_VERSION)-$(REVISION).$(PLATFORM).rpm

bin_PROGRAMS = lprobe

# lprobe
lprobe_SOURCES = lprobe.c
lprobe_DEPENDENCIES = liblprobe.la
lprobe_LDADD = liblprobe.la
lprobe_LDFLAGS = $(AM_LDFLAGS) -pthread -lm
lprobe_CFLAGS =

lib_LTLIBRARIES = liblprobe.la

# lprobe core library

#
# On old systems getopt might be undefined
#
GETOPT_FILES=#getopt1.c getopt.c
liblprobe_la_SOURCES = cache.c collect.c engine.c export.c database.c \
		       $(GETOPT_FILES) globals.c plugin.c template.c \
		       sflow_collect.c util.c version.c systemId.c $(PF_RING)
liblprobe_la_LDFLAGS = $(AM_LDFLAGS) -release $(VERSION) -export-dynamic @DYN_FLAGS@
liblprobe_la_DEPENDENCIES = @USE_LICENSE@

private/license/liblicense.a:
	cd private/license; make

#
# We need to compile it this way as the -fPIC libtool directive
# will break the logic
#

#systemId.o: systemId.c Makefile @USE_LICENSE@
#	gcc $(CFLAGS) -I@HERE@ @PIC@ -c systemId.c

cleanup-rpm:
	rm -rf $(HOME)/rpmbuild/BUILD/lprobe* $(HOME)/rpmbuild/SOURCES/lprobe*

cleanup-n2disk-rpm:
	rm -rf $(HOME)/rpmbuild/BUILD/n2disk* $(HOME)/rpmbuild/SOURCES/lprobe*

build-rpm: build-lprobe-rpm build-n2disk-rpm

build-lprobe-rpm: cleanup-rpm maketarproplugins datfiles $(APPL)
# Do NOT build package as root (http://wiki.centos.org/HowTos/SetupRpmBuildEnvironment)
#	mkdir -p $(HOME)/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
#	echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros
	-rm -rf lprobe-@PACKAGE_VERSION@
	cp -rf lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins lprobe-@PACKAGE_VERSION@
	mkdir -p lprobe-@PACKAGE_VERSION@/packages
	cp packages/*.spec.in lprobe-@PACKAGE_VERSION@/packages
	cp -rf pro lprobe-@PACKAGE_VERSION@
	cp -rf private lprobe-@PACKAGE_VERSION@
	cp *.dat COPYING LICENSE EULA.txt lprobe-@PACKAGE_VERSION@
	cp plugins/bgpPlugin.c plugins/dbPlugin.c plugins/dnsPlugin.c \
	plugins/httpPlugin.c plugins/mysqlPlugin.c plugins/nflitePlugin.c \
	plugins/rtpPlugin.c plugins/sipPlugin.c plugins/smtpPlugin.c \
	plugins/radiusPlugin.c plugins/gtpv1Plugin.c plugins/gtpv0Plugin.c plugins/gtpv2Plugin.c lprobe-@PACKAGE_VERSION@/plugins
	tar cvfz $(HOME)/rpmbuild/SOURCES/lprobe-@PACKAGE_VERSION@.tgz lprobe-@PACKAGE_VERSION@
	@rm -f $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(PKG)
	@cp $(APPL) $(HOME)/rpmbuild/BUILD
	@rpmbuild -bb ./packages/$(APPL).spec --define "buildnumber $(REVISION)"
	@./packages/rpm-sign.exp $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(PKG)
	@echo ""
	@echo "Package contents:"
	@rpm -qpl $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(PKG)
	@echo "The package is now available in $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(PKG)"

build-n2disk-rpm: maketarproplugins
# Do NOT build package as root (http://wiki.centos.org/HowTos/SetupRpmBuildEnvironment)
#	mkdir -p $(HOME)/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
#	echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros
	\/bin/rm -rf n2disk-@N2DISK_PACKAGE_VERSION@
	cp -rf lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins n2disk-@N2DISK_PACKAGE_VERSION@
	mkdir -p n2disk-@N2DISK_PACKAGE_VERSION@/packages
	cp packages/*.spec.in n2disk-@N2DISK_PACKAGE_VERSION@/packages
	cp -rf pro n2disk-@N2DISK_PACKAGE_VERSION@
	cp -rf private n2disk-@N2DISK_PACKAGE_VERSION@
	tar cvfz $(HOME)/rpmbuild/SOURCES/n2disk-@N2DISK_PACKAGE_VERSION@.tgz n2disk-@N2DISK_PACKAGE_VERSION@
	rm -f $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(N2DISK_PKG)
	rpmbuild -bb ./packages/n2disk.spec --define "buildnumber $(REVISION)"
	@./packages/rpm-sign.exp $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(N2DISK_PKG)
	@echo ""
	@echo "Package contents:"
	@rpm -qpl $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(N2DISK_PKG)
	@echo "The package is now available in $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(N2DISK_PKG)"


build-n2disknt-rpm: maketarproplugins
# Do NOT build package as root (http://wiki.centos.org/HowTos/SetupRpmBuildEnvironment)
#	mkdir -p $(HOME)/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
#	echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros
	\/bin/rm -rf n2disknt-@N2DISK_PACKAGE_VERSION@
	cp -rf lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins n2disknt-@N2DISK_PACKAGE_VERSION@
	mkdir -p n2disknt-@N2DISK_PACKAGE_VERSION@/packages
	cp packages/*.spec.in n2disknt-@N2DISK_PACKAGE_VERSION@/packages
	cp -rf pro n2disknt-@N2DISK_PACKAGE_VERSION@
	cp -rf private n2disknt-@N2DISK_PACKAGE_VERSION@
	tar cvfz $(HOME)/rpmbuild/SOURCES/n2disknt-@N2DISK_PACKAGE_VERSION@.tgz n2disknt-@N2DISK_PACKAGE_VERSION@
	rm -f $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(N2DISKNT_PKG)
	rpmbuild -bb ./packages/n2disknt.spec --define "buildnumber $(REVISION)"
	@./packages/rpm-sign.exp $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(N2DISKNT_PKG)
	@echo ""
	@echo "Package contents:"
	@rpm -qpl $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(N2DISKNT_PKG)
	@echo "The package is now available in $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(N2DISKNT_PKG)"
	-rm -rf lprobe-@N2DISK_PACKAGE_VERSION@ lprobe_@N2DISK_PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins.tgz

CLEANLIST = `ls -l $(DESTDIR)$(libdir)/*lprobe*.so $(DESTDIR)$(libdir)/*Plugin*.so | \
          grep -v $(VERSION) | \
          grep -v '\->' | \
          $(AWK) '{ print $$NF }'`

listlibclean:
	@echo ""
	@echo "This is a list of old shared library files that will be deleted"
	@echo "if you run 'make libclean'"
	@echo ""
	@for file in $(CLEANLIST); do \
          if test -f $$file; then \
             echo "   $$file"; \
          fi; \
        done
	@echo ""

libclean:
	@echo ""
	@echo "Cleanup of old shared library files..."
	@echo ""
	@echo "  This is a list of files that will be deleted..."
	@echo ""
	@for file in $(CLEANLIST); do \
          if test -f $$file; then \
             echo "   $$file"; \
          fi; \
        done
	@echo ""
	@echo ""
	@echo "Press cntl-c to stop or enter to continue and delete these files..."
	@read select
	@echo ""
	@for file in $(CLEANLIST); do \
          if test -f $$file; then \
             echo "   ...Deleting $$file"; \
             rm -f $$file; \
          fi; \
        done


clean:
	/bin/rm -rf $(CLEANFILES)

lprobes: $(lprobe_OBJECTS) $(lprobe_DEPENDENCIES)
	cd plugins;make
#	$(CC) -static *.o plugins/*.o -o lprobes  -lpcap -lpthread -ldl $(LIBS)
	$(CC)  *.o plugins/*.o -o lprobes -lpthread -ldl -lresolv -ldl -lpthread -L./private/license -llicense $(LIBS) @NDPI_LIB@ $(HOME)/PF_RING/userland/libpcap/libpcap.a $(HOME)/PF_RING/userland/lib/libpfring.a

############

SVN_RELEASE=svn`svn info . | grep "^Revision"|cut -d " " -f 2`

maketar: @GEOIP_TARGET@
	\rm -rf lprobe_@PACKAGE_VERSION@_*
	mkdir lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)
	mkdir lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)/packages
	mkdir lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)/utils
	cp COPYING LICENSE EULA.txt lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)
	cp python-config lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)
	cp -rf *.c *.h third_party lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)
	cp README *.in autogen.sh Makefile.am lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)
	cp packages/*.spec.in lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)/packages
	cp utils/*[ch] utils/Makefile.in lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)/utils
	grep -v 'private/Makefile' configure.am | grep -v n2disk_version.h| sed -e 's/AC_CONFIG_FILES(\[plugins\/Makefile\])/echo ""/g' | sed -e 's/PLUGINS=plugins/PLUGINS=/g' > lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)/configure.am
	\rm -f lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)/libtool
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE) -name "#*"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE) -name "*~"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE) -name "svn-commit*"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE) -type f -name "*.dSYM"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE) -type d -name ".svn"  -print | xargs /bin/rm -rf
	tar cvfz ./lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE).tgz ./lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)

maketarproplugins: @GEOIP_TARGET@
	\rm -rf lprobe_@PACKAGE_VERSION@_*_proplugins
	mkdir lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins
	mkdir lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/plugins
	mkdir lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/bgp
	mkdir lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/packages
	mkdir lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/utils
	cp COPYING LICENSE EULA.txt lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins
	cp python-config lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins
	cp packages/*.spec.in lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/packages
	cp bgp/bgp_probe_client.pl bgp/README lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/bgp
	cp -rf pro *.c *.h third_party lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins
	cp utils/*[ch] utils/Makefile.in lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/utils
	cp plugins/buildMakefile.sh lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/plugins
	cp plugins/bgpPlugin.c lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/plugins
	cp plugins/patricia.[ch] lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/plugins
	cp plugins/dbPlugin.c lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/plugins
	cp README *.in autogen.sh Makefile.am configure.am lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins
	\rm -f lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/plugins/ltop*
	grep -v 'private/Makefile' configure.am | grep -v n2disk_version.h> lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/configure.am
	\rm -f lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins/libtool
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins -type f -name "*.bak"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins -type f -name "#*"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins -type f -name "*~"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins -type f -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins.tgz ./lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_proplugins

maketarfranz: @GEOIP_TARGET@
	\rm -rf lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz
	mkdir lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz
	mkdir lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	mkdir lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/packages
	mkdir lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/utils
	mkdir lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/extensions
	cp python-config lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz
	cp utils/*[ch] utils/Makefile.in lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/utils
	cp COPYING LICENSE EULA.txt lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz
	cp packages/*.spec.in lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/packages
	cp -rf pro *.c *.h third_party lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz
	cp plugins/buildMakefile.sh lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/dbPlugin.c lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/ftpPlugin.c lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/httpPlugin.c lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/mysqlPlugin.c lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/dhcpPlugin.c lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/rtpPlugin.c lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/sipPlugin.c lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/smtpPlugin.c lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/popPlugin.c lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/imapPlugin.c lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp plugins/radiusPlugin.c lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins
	cp extensions/*.[ch] lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/extensions
	cp README *.in autogen.sh Makefile.am configure.am lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz
	\rm -f lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugins/ltop*
	grep -v 'private/Makefile' configure.am | grep -v n2disk_version.h > lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/configure.am
	cp -r plugin_sdk lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/
	\rm -f lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/plugin_sdk/Makefile
	\rm -f lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz/libtool
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz -type f -name "*.bak"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz -type f -name "#*"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz -type f -name "*~"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz -type f -name "*.dSYM"  -print | xargs /bin/rm -rf
	cd lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz; svn co https://svn.ltop.org/svn/ltop/trunk/nDPI/; \find . -name ".svn"|xargs /bin/rm -rf {} ';'
	tar cvfz ./lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz.tgz ./lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_franz

maketarhomer: @GEOIP_TARGET@
	\rm -rf lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer
	mkdir lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer
	mkdir lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/plugins
	mkdir lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/packages
	mkdir lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/utils
	mkdir lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/extensions
	cp python-config lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer
	cp utils/*[ch] utils/Makefile.in lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/utils
	cp COPYING LICENSE EULA.txt lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer
	cp packages/*.spec.in lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/packages
	cp -rf pro *.c *.h third_party lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer
	cp plugins/buildMakefile.sh lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/plugins
	cp plugins/homerRtpPlugin.c lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/plugins
	cp plugins/homerSipPlugin.c lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/plugins
	cp plugins/mos.[ch] lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/plugins
	cp plugins/hep.h lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/plugins
	cp extensions/*.[ch] lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/extensions
	cp README *.in autogen.sh Makefile.am configure.am lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer
	\rm -f lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/plugins/ltop*
	grep -v 'private/Makefile' configure.am | grep -v n2disk_version.h > lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/configure.am
	cp -r plugin_sdk lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/
	\rm -f lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/plugin_sdk/Makefile
	\rm -f lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer/libtool
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer -type f -name "*.bak"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer -type f -name "#*"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer -type f -name "*~"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer -type f -name "*.dSYM"  -print | xargs /bin/rm -rf
	cd lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer; svn co https://svn.ltop.org/svn/ltop/trunk/nDPI/; \find . -name ".svn"|xargs /bin/rm -rf {} ';'
	tar cvfz ./lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer.tgz ./lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_homer

maketarnflite:
	\rm -rf lprobe_@PACKAGE_VERSION@_*_nflite
	mkdir -p lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite/lprobe/plugins
	mkdir -p lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite/PF_RING/NFLite/kernel
	mkdir -p lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite/PF_RING/NFLite/userland
	cp plugins/README.plugins plugins/nflitePlugin.c lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite/lprobe/plugins
#	cp private/PF_RING/NFLite/README private/PF_RING/NFLite/Makefile lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite/PF_RING/NFLite/
#	cp private/PF_RING/NFLite/kernel/Makefile private/PF_RING/NFLite/kernel/nflite_plugin.[ch] lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite/PF_RING/NFLite/kernel
#	cp private/PF_RING/NFLite/userland/nflite_dump.c private/PF_RING/NFLite/userland/Makefile lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite/PF_RING/NFLite/userland
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite -type f -name "*.bak"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite -type f -name "#*"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite -type f -name "*~"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite -type f -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite.tgz ./lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_nflite

maketardns:
	\rm -rf lprobe_@PACKAGE_VERSION@_*_dns
	mkdir -p lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_dns/lprobe/plugins
	cp plugins/README.plugins plugins/dnsPlugin.c lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_dns/lprobe/plugins
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_dns -type f -name "*.bak"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_dns -type f -name "#*"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_dns -type f -name "*~"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_dns -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_dns -type f -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_dns.tgz ./lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_dns

maketarhttp:
	\rm -rf lprobe_@PACKAGE_VERSION@_*_http
	mkdir -p lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_http/lprobe/plugins
	cp plugins/README.plugins plugins/httpPlugin.c lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_http/lprobe/plugins
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_http -type f -name "*.bak"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_http -type f -name "#*"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_http -type f -name "*~"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_http -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_http -type f -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_http.tgz ./lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_http

maketaremail:
	\rm -rf lprobe_@PACKAGE_VERSION@_*_email
	mkdir -p lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_email/lprobe/plugins
	cp plugins/README.plugins plugins/popPlugin.c plugins/smtpPlugin.c plugins/imapPlugin.c lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_email/lprobe/plugins
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_email -type f -name "*.bak"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_email -type f -name "#*"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_email -type f -name "*~"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_email -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_email -type f -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_email.tgz ./lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_email

maketarvoip:
	\rm -rf lprobe_@PACKAGE_VERSION@_*_voip
	mkdir -p lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_voip/lprobe/plugins
	cp plugins/README.plugins plugins/sipPlugin.c plugins/rtpPlugin.c lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_voip/lprobe/plugins
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_voip -type f -name "*.bak"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_voip -type f -name "#*"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_voip -type f -name "*~"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_voip -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_voip -type f -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_voip.tgz ./lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_voip

maketaroracle:
	\rm -rf lprobe_@PACKAGE_VERSION@_*_oracle
	mkdir -p lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_oracle/lprobe/plugins
	cp plugins/README.plugins plugins/oraclePlugin.c lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_oracle/lprobe/plugins
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_oracle -type f -name "*.bak"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_oracle -type f -name "#*"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_oracle -type f -name "*~"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_oracle -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_oracle -type f -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_oracle.tgz ./lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_oracle

maketarmysql:
	\rm -rf lprobe_@PACKAGE_VERSION@_*_mysql
	mkdir -p lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_mysql/lprobe/plugins
	cp plugins/README.plugins plugins/mysqlPlugin.c lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_mysql/lprobe/plugins
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_mysql -type f -name "*.bak"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_mysql -type f -name "#*"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_mysql -type f -name "*~"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_mysql -type d -name ".svn"  -print | xargs /bin/rm -rf
	\find lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_mysql -type f -name "*.dSYM"  -print | xargs /bin/rm -rf
	tar cvfz ./lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_mysql.tgz ./lprobe_@PACKAGE_VERSION@_$(SVN_RELEASE)_mysql

tar: maketar maketarproplugins maketarnflite maketarhttp maketardns maketaroracle maketarmysql maketaremail maketarvoip # maketarfranz

binarytar:
	\rm -rf lprobe_@PACKAGE_VERSION@-@PLATFORM@_$(SVN_RELEASE)
	mkdir lprobe_@PACKAGE_VERSION@-@PLATFORM@_$(SVN_RELEASE) lprobe_@PACKAGE_VERSION@-@PLATFORM@_$(SVN_RELEASE)/plugins
	cp .libs/lprobe .libs/liblprobe-@PACKAGE_VERSION@.so .libs/liblprobe.so lprobe_@PACKAGE_VERSION@-@PLATFORM@_$(SVN_RELEASE)
	cp plugins/.libs/lib*Plugin-@PACKAGE_VERSION@.so lprobe_@PACKAGE_VERSION@-@PLATFORM@_$(SVN_RELEASE)/plugins
	tar cvfz lprobe_@PACKAGE_VERSION@-@PLATFORM@_$(SVN_RELEASE).tgz lprobe_@PACKAGE_VERSION@-@PLATFORM@_$(SVN_RELEASE)

install: install-recursive	

datfiles: GeoLiteCity.dat GeoIPASNum.dat GeoIPASNumv6.dat GeoLiteCityv6.dat

GeoLiteCity.dat:
	if test -f $(HOME)/dat_files/$@.gz; then \
		cp  $(HOME)/dat_files/$@.gz .; \
	else \
		wget http://www.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz; \
	fi
	gunzip GeoLiteCity.dat.gz

GeoIPASNum.dat:
	if test -f $(HOME)/dat_files/$@.gz; then \
		cp  $(HOME)/dat_files/$@.gz .; \
	else \
		wget http://www.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz; \
	fi
	gunzip GeoIPASNum.dat.gz

GeoIPASNumv6.dat:
	if test -f $(HOME)/dat_files/$@.gz; then \
		cp  $(HOME)/dat_files/$@.gz .; \
	else \
		wget http://www.maxmind.com/download/geoip/database/asnum/GeoIPASNumv6.dat.gz; \
	fi
	gunzip GeoIPASNumv6.dat.gz

GeoLiteCityv6.dat:
	if test -f $(HOME)/dat_files/$@.gz; then \
		cp  $(HOME)/dat_files/$@.gz .; \
	else \
		wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/GeoLiteCityv6.dat.gz; \
	fi
	gunzip GeoLiteCityv6.dat.gz
