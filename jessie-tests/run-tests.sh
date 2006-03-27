#!/bin/sh

test -z "$JAVAC"        && export JAVAC=jikes
test -z "$JAVA"         && export JAVA=jamvm
test -z "$JAVA_OPTIONS" && export JAVA_OPTIONS=
test -z "$CLASSPATH"    && export CLASSPATH=.

tests="gnu.javax.net.ssl.provider.testAlert \
       gnu.javax.net.ssl.provider.testCertificate \
       gnu.javax.net.ssl.provider.testCertificateRequest \
       gnu.javax.net.ssl.provider.testCipherSuiteList \
       gnu.javax.net.ssl.provider.testClientHello \
       gnu.javax.net.ssl.provider.testCompressionMethodList \
       gnu.javax.net.ssl.provider.testHelloRequest \
       gnu.javax.net.ssl.provider.testRecord \
       gnu.javax.net.ssl.provider.testServerDHParams \
       gnu.javax.net.ssl.provider.testServerHello \
       gnu.javax.net.ssl.provider.testServerRSAParams"

rm -rf test-classes
mkdir test-classes
${JAVAC} -d test-classes gnu/javax/net/ssl/provider/*.java || exit 1

fails=0
rm -rf check.log check.err
echo -n "Jessie check run at " | tee check.err > check.log
date | tee -a check.err >> check.log
for test in $tests
do
  echo $test
  echo ---- $test ---- >> check.err
  if `(${JAVA} ${JAVA_OPTIONS} -cp ${CLASSPATH}:test-classes $test 2>> check.err || echo FAIL: $test) | tee -a check.log | grep -q ^FAIL > /dev/null`
      then
      echo FAIL: $test
      let 'fails = fails + 1'
  fi
done

if test ${fails} -eq 1
then
    echo $fails failure
    echo ---- $fails failure ---- >> check.err
else
    echo $fails failures
    echo ---- $fails failures ---- >> check.err
fi
echo -n "Jessie check done at " >> check.err
date >> check.err

if test ${fails} -gt 0
    then
    exit 1
fi
