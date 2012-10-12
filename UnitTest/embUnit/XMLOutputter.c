/*
 * COPYRIGHT AND PERMISSION NOTICE
 * 
 * Copyright (c) 2003 Embedded Unit Project
 * 
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the 
 * "Software"), to deal in the Software without restriction, including 
 * without limitation the rights to use, copy, modify, merge, publish, 
 * distribute, and/or sell copies of the Software, and to permit persons 
 * to whom the Software is furnished to do so, provided that the above 
 * copyright notice(s) and this permission notice appear in all copies 
 * of the Software and that both the above copyright notice(s) and this 
 * permission notice appear in supporting documentation.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT 
 * OF THIRD PARTY RIGHTS. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
 * HOLDERS INCLUDED IN THIS NOTICE BE LIABLE FOR ANY CLAIM, OR ANY 
 * SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER 
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF 
 * CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN 
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 * Except as contained in this notice, the name of a copyright holder 
 * shall not be used in advertising or otherwise to promote the sale, 
 * use or other dealings in this Software without prior written 
 * authorization of the copyright holder.
 *
 * $Id: XMLOutputter.c,v 1.6 2003/09/26 16:32:01 arms22 Exp $
 */
#include "config.h"
#include "XMLOutputter.h"

static char *stylesheet_;
static char *xmlfilename=NULL;

static void XMLOutputter_printHeader(OutputterRef self)
{
	if(xmlfilename==NULL)
	{
		xmlfilename="emb_XML_test";
	}
	
	set_printk_prefix("[EMBUNIT]");
	stdimpl_print("[START]%s\n",xmlfilename);
	stdimpl_print("<?xml version=\"1.0\" ?> \n");
	stdimpl_print("<?xml-stylesheet type=\"text/xsl\" href=\"CUnit-Run.xsl\" ?> \n");
	stdimpl_print("<!DOCTYPE CUNIT_TEST_RUN_REPORT SYSTEM \"CUnit-Run.dtd\"> \n");
	stdimpl_print("<CUNIT_TEST_RUN_REPORT> \n");
	stdimpl_print("  <CUNIT_HEADER/> \n");

	stdimpl_print("  <CUNIT_RESULT_LISTING> \n");
	//fprintf(stdout,"<?xml version=\"1.0\" encoding='shift_jis' standalone='yes' ?>\n");
	//if (stylesheet_)
	//fprintf(stdout,"<?xml-stylesheet type=\"text/xsl\" href=\"%s\" ?>\n",stylesheet_);
	//fprintf(stdout,"<TestRun>\n");
}

static void XMLOutputter_printStartTest(OutputterRef self,TestRef test)
{
	stdimpl_print("    <CUNIT_RUN_SUITE> \n");
	stdimpl_print("      <CUNIT_RUN_SUITE_SUCCESS> \n");
	stdimpl_print("        <SUITE_NAME> %s </SUITE_NAME> \n",
			(NULL != Test_name(test)) ? Test_name(test) : "");
	
	//fprintf(stdout,"<%s>\n",Test_name(test));
}

static void XMLOutputter_printEndTest(OutputterRef self,TestRef test)
{
	 stdimpl_print("      </CUNIT_RUN_SUITE_SUCCESS> \n");
	 stdimpl_print("    </CUNIT_RUN_SUITE> \n");
	//fprintf(stdout,"</%s>\n",Test_name(test));
}

static void XMLOutputter_printSuccessful(OutputterRef self,TestRef test,int runCount)
{
	stdimpl_print("        <CUNIT_RUN_TEST_RECORD> \n");
	stdimpl_print("          <CUNIT_RUN_TEST_SUCCESS> \n");
	stdimpl_print("            <TEST_NAME> %s </TEST_NAME> \n",
			(NULL != Test_name(test)) ? Test_name(test) : "");
	stdimpl_print("          </CUNIT_RUN_TEST_SUCCESS> \n");
	stdimpl_print("        </CUNIT_RUN_TEST_RECORD> \n");
	//fprintf(stdout,"<Test id=\"%d\">\n",runCount);
	//fprintf(stdout,"<Name>%s</Name>\n",Test_name(test));
	//fprintf(stdout,"</Test>\n");
}

/** Structure containing mappings of special characters to
 **  xml entity codes.
 **/
static const struct {
		char special_char;
			char* replacement;
} bindings [] = {
	    {'&', "&amp;"},
	    {'>', "&gt;"},
	    {'<', "&lt;"}
};
/** Maximum string length. */
#define CUNIT_MAX_STRING_LENGTH	1024
/** maximum number of characters in a translated xml entity. */
#define CUNIT_MAX_ENTITY_LEN 5
static int get_index(char ch)
{
	int length = sizeof(bindings)/sizeof(bindings[0]);
	int counter;
	
	for (counter = 0; counter < length && bindings[counter].special_char != ch; ++counter) {
		;
	}
	
	return (counter < length ? counter : -1);
}

int translate_special_characters(const char* szSrc, char* szDest, size_t maxlen)
{
	int count = 0;
	size_t src = 0;
	size_t dest = 0;
	size_t length = stdimpl_strlen(szSrc);
	int conv_index;
	
	if(szSrc == NULL || szDest==NULL){
		szDest[0]=0;
		return 0;
	}
	
	
	while ((dest < maxlen) && (src < length)) {
		
		if ((-1 != (conv_index = get_index(szSrc[src]))) &&
				((dest + (int)stdimpl_strlen(bindings[conv_index].replacement)) <= maxlen)) {
			stdimpl_strcat(szDest, bindings[conv_index].replacement);
			dest += (int)stdimpl_strlen(bindings[conv_index].replacement);
			++count;
		} else {
			szDest[dest++] = szSrc[src];
		}
		
		++src;
	}
	szDest[dest]=0;
	return count;
}

static void XMLOutputter_printFailure(OutputterRef self,TestRef test,char *msg,char *strCondition, int line,char *file,int runCount)
{
	/* worst cast is a string of special chars */
	char szTemp[CUNIT_MAX_ENTITY_LEN * CUNIT_MAX_STRING_LENGTH]={""};
	
	translate_special_characters(strCondition, szTemp, sizeof(szTemp));
	
	stdimpl_print("        <CUNIT_RUN_TEST_RECORD> \n");
	stdimpl_print("          <CUNIT_RUN_TEST_FAILURE> \n");
	stdimpl_print("            <TEST_NAME> %s </TEST_NAME> \n",
			(NULL != Test_name(test)) ? Test_name(test) : "");
	stdimpl_print("            <FILE_NAME> %s </FILE_NAME> \n",
			(NULL != file) ? file : "");
	stdimpl_print("            <LINE_NUMBER> %u </LINE_NUMBER> \n",line);
	stdimpl_print("            <CONDITION> %s //%s </CONDITION> \n",
			szTemp,msg);
	stdimpl_print("          </CUNIT_RUN_TEST_FAILURE> \n");
	stdimpl_print("        </CUNIT_RUN_TEST_RECORD> \n");
	
	//firintf(stdout,"<FailedTest id=\"%d\">\n",runCount);
	//fprintf(stdout,"<Name>%s</Name>\n",Test_name(test));
	//fprintf(stdout,"<Location>\n");
	//fprintf(stdout,"<File>%s</File>\n",file);
	//fprintf(stdout,"<Line>%d</Line>\n",line);
	//fprintf(stdout,"</Location>\n");
	//fprintf(stdout,"<Message>%s</Message>\n",msg);
	//fprintf(stdout,"</FailedTest>\n");
}

static void XMLOutputter_printStatistics(OutputterRef self,TestResultRef result)
{
	stdimpl_print("  </CUNIT_RESULT_LISTING>\n");
	stdimpl_print("  <CUNIT_RUN_SUMMARY> \n");

	 /* fprintf(stdout,
	          "    <CUNIT_RUN_SUMMARY_RECORD> \n"
	          "      <TYPE> Suites </TYPE> \n"
	          "      <TOTAL> %u </TOTAL> \n"
	          "      <RUN> %u </RUN> \n"
	          "      <SUCCEEDED> - NA - </SUCCEEDED> \n"
	          "      <FAILED> %u </FAILED> \n"
	          "    </CUNIT_RUN_SUMMARY_RECORD> \n",
	          pRegistry->uiNumberOfSuites,
	          pRunSummary->nSuitesRun,
	          pRunSummary->nSuitesFailed
	          );
*/
	 stdimpl_print("    <CUNIT_RUN_SUMMARY_RECORD> \n");
	 stdimpl_print("      <TYPE> Test Cases </TYPE> \n");
	 stdimpl_print("      <RUN> %u </RUN> \n",result->runCount);
	 stdimpl_print("      <SUCCEEDED> %u </SUCCEEDED> \n",
			 result->runCount- result->failureCount);
	 stdimpl_print("      <FAILED> %u </FAILED> \n",result->failureCount);
	 stdimpl_print("    </CUNIT_RUN_SUMMARY_RECORD> \n");

	stdimpl_print("  </CUNIT_RUN_SUMMARY> \n");
	
	stdimpl_print("</CUNIT_TEST_RUN_REPORT>\n");
	stdimpl_print("[END]%s\n",xmlfilename);
	set_printk_prefix("[XEN] ");
	xmlfilename=NULL;
	
	//fprintf(stdout,"<Statistics>\n");
	//fprintf(stdout,"<Tests>%d</Tests>\n",result->runCount);
	//if (result->failureCount) {
	//fprintf(stdout,"<Failures>%d</Failures>\n",result->failureCount);
	//}
	//fprintf(stdout,"</Statistics>\n");
	//fprintf(stdout,"</TestRun>\n");
}

static const OutputterImplement XMLOutputterImplement = {
	(OutputterPrintHeaderFunction)		XMLOutputter_printHeader,
	(OutputterPrintStartTestFunction)	XMLOutputter_printStartTest,
	(OutputterPrintEndTestFunction)		XMLOutputter_printEndTest,
	(OutputterPrintSuccessfulFunction)	XMLOutputter_printSuccessful,
	(OutputterPrintFailureFunction)		XMLOutputter_printFailure,
	(OutputterPrintStatisticsFunction)	XMLOutputter_printStatistics,
};

static const Outputter XMLOutputter = {
	(OutputterImplementRef)&XMLOutputterImplement,
};

void XMLOutputter_setFileName(char *name)
{
	xmlfilename = name;
}

void XMLOutputter_setStyleSheet(char *style)
{
	stylesheet_ = style;
}

OutputterRef XMLOutputter_outputter(void)
{
	return (OutputterRef)&XMLOutputter;
}
