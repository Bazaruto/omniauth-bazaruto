source "https://rubygems.org"

git_source(:github) {|repo_name| "https://github.com/#{repo_name}" }

# Specify your gem's dependencies in omniauth-bazaruto.gemspec
gemspec

gem "minitest", ">= 5.25", "< 7"
gem "webmock", "~> 3.26"

# Exercise both Rack generations without changing the library's runtime constraint.
gem "rack", ENV.fetch("RACK_VERSION", ">= 2.2.8")
