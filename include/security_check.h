#ifndef SECURITY_CHECK_H
#define SECURITY_CHECK_H

#include "i18n.h"
#include "url_parser.h"

char *security_check_report(const ParsedUrl *url, const char *final_url,
                            Language language);

#endif
