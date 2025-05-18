Use this command if the templete dosen't work.

sudo bundle update --bundler

If the update give issues use the following commnnds:

gem uninstall bundler
gem install bundler
rm Gemfile.lock
bundle install

Run the jekyll in local live.

sudo bundle exec jekyll serve --livereload --host 0.0.0.0
