#!/bin/bash

# Clone and checkout specific commits for each repository
git clone https://github.com/openssh/openssh-portable.git test_lib/openssh-portable
cd test_lib/openssh-portable
git checkout 5f93c4836527d9fda05de8944a1c7b4a205080c7
cd ../..

git clone https://github.com/openssl/openssl.git test_lib/openssl
cd test_lib/openssl
git checkout 894f2166ef2c16d8e4533e1c09e05ff31ea2f1d8
cd ../..

git clone https://github.com/tmux/tmux test_lib/tmux
cd test_lib/tmux
git checkout 70ff8cfe1e06987501a55a32df31d1f69acd2f99
cd ../..

git clone https://github.com/andrew-d/rough-auditing-tool-for-security.git tools/rats
cd tools/rats
git checkout 4ba54ce278e9fb004d978e924fd63c29e449ca81
cd ../..

git clone https://github.com/srcML/srcML.git tools/srcml
cd tools/srcml
git checkout e5af3c1a295afd81f0ff9e3ada2ac8ad092b89fb
cd ../..

