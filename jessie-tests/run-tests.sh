#!/bin/sh

test -z "$JAVAC"        && export JAVAC=jikes
test -z "$JAVA"         && export JAVA=jamvm
test -z "$JAVA_OPTIONS" && export JAVA_OPTIONS=
test -z "$CLASSPATH"    && export CLASSPATH=.

tests="testAlert testCertificate testCertificateRequest \
       testCipherSuiteList testClientHello testCompressionMethodList \
       testHelloRequest testRecord testServerDHParams \
       testServerHello testServerHelloDone testServerKeyExchange \
       testServerRSAParams testSignature"

rm -rf test-classes
mkdir test-classes
${JAVAC} -cp $CLASSPATH -d test-classes *.java || exit 1

ntests=0
fails=0
rm -rf check.log check.err
echo -n "Jessie check run at " | tee check.err > check.log
date | tee -a check.err >> check.log
for test in $tests
do
  echo $test
  echo ---- $test ---- >> check.log
  echo ---- $test ---- >> check.err
  if `(${JAVA} ${JAVA_OPTIONS} -cp ${CLASSPATH}:test-classes $test 2>> check.err || echo FAIL: $test) | tee -a check.log | grep -q ^FAIL > /dev/null`
      then
      echo FAIL: $test
      let 'fails = fails + 1'
  fi
  let 'ntests = ntests + 1'
done

if test ${fails} -eq 1
then
    echo $ntests tests, $fails failure
    echo ---- $ntests tests, $fails failure ---- >> check.err
else
    echo $ntests tests, $fails failures
    echo ---- $ntests tests, $fails failures ---- >> check.err
fi
echo -n "Jessie check done at " | tee -a check.err >> check.log
date | tee -a check.err >> check.log

if test ${fails} -gt 0
    then
    exit 1
fi
