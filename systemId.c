/*
 *
 *       Copyright (C) 2002-14 Luca Deri <deri@ltop.org>
 *
 *                     http://www.ltop.org/
 *
 */

#define _lprobe_H_ /* Trick */

#include "lprobe.h"
#include "config.h"
#include <string.h>

#ifdef HAVE_LICENSE

#ifdef WIN32
#include "private/license/systemId_win32.c"
#else
#include "private/license/systemId.c"
#endif

#else

char* getSystemId() { return(strdup("")); }

#endif

