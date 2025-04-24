require 'sinatra'
require 'json'
require 'fileutils'
require 'open3'
require 'securerandom'

set :public_folder, File.dirname(__FILE__) + '/public'
set :views, File.dirname(__FILE__) + '/views'

$dashboard_data = {}

# Homepage
get '/' do
  erb :index
end

# JSON Export Route
get '/export_json' do
  content_type :json

  if $dashboard_data && $dashboard_data[:results]
    filename = $dashboard_data[:filename] || "scan_results"
    headers["Content-Disposition"] = "attachment; filename=\"#{filename.gsub(' ', '_')}.json\""
    $dashboard_data[:results].to_json
  else
    halt 404, { error: "No data available to export." }.to_json
  end
end

# Dashboard View
get '/dashboard' do
  data = $dashboard_data
  erb :dashboard, locals: {
    filename: data[:filename],
    issues: data[:results],
    total_issues: data[:results].size
  }
end

# File Upload Analyzer
post '/analyze' do
  if params[:file] && params[:file][:tempfile]
    file = params[:file][:tempfile]
    filename = params[:file][:filename]

    FileUtils.mkdir_p('uploads')
    path = "uploads/#{filename}"
    File.open(path, 'wb') { |f| f.write(file.read) }

    ext = File.extname(filename).downcase
    rules = analyzer_rules
    rules[ext] ||= []

    issues = scan_file(path, ext, rules)

    $dashboard_data = {
      filename: filename,
      results: issues
    }

    redirect '/dashboard'
  else
    redirect '/'
  end
end

# GitHub Repo Analyzer
post '/analyze_github' do
  url = params[:repo_url]
  unless url =~ /^https:\/\/github.com\/[\w\-]+\/[\w\-]+$/
    return "❌ Invalid GitHub URL format. Example: https://github.com/username/repo"
  end

  repo_id = SecureRandom.hex(6)
  repo_path = "./repos/#{repo_id}"
  FileUtils.mkdir_p(repo_path)

  clone_cmd = "git clone --depth 1 #{url}.git #{repo_path}"
  stdout, stderr, status = Open3.capture3(clone_cmd)

  unless status.success?
    return "❌ Git clone failed:\n#{stderr}"
  end

  extensions = [".rb", ".py", ".js"]
  rules = analyzer_rules
  issues = []

  Dir.glob("#{repo_path}/**/*").each do |file|
    ext = File.extname(file)
    next unless extensions.include?(ext)

    file_issues = scan_file(file, ext, rules).map do |issue|
      issue.merge({ file: file.gsub("#{repo_path}/", '') })
    end

    issues.concat(file_issues)
  end

  $dashboard_data = {
    filename: "GitHub Repo: #{url}",
    results: issues
  }

  redirect '/dashboard'
end

# Extract reusable analyzer rules
def analyzer_rules
  {
    ".rb" => [
      { pattern: /eval/, message: "⚠️ Use of `eval`", suggestion: "Avoid using `eval`. Try `send` or refactor logic." },
      { pattern: /password\s*=\s*['"].+['"]/, message: "🔐 Hardcoded password", suggestion: "Use environment variables or a secrets manager." },
      { pattern: /`.+`/, message: "💣 Backtick system call", suggestion: "Use safer APIs like Open3." }
    ],
    ".py" => [
      { pattern: /exec\(.+\)/, message: "⚠️ Use of `exec()`", suggestion: "Avoid `exec()` — it's unsafe." },
      { pattern: /input\(.+\)/, message: "🟡 Unsanitized `input()`", suggestion: "Always sanitize user input." },
      { pattern: /password\s*=\s*['"].+['"]/, message: "🔐 Hardcoded password", suggestion: "Store in `.env` or config files." }
    ],
    ".js" => [
      { pattern: /eval\(.+\)/, message: "⚠️ Use of `eval()`", suggestion: "Avoid using `eval()`. It’s a major security risk." },
      { pattern: /document\.write/, message: "🟡 Use of `document.write()`", suggestion: "Avoid it for performance & security reasons." },
      { pattern: /innerHTML\s*=/, message: "🔓 Risky `innerHTML` usage", suggestion: "Sanitize any dynamic input or use `textContent`." }
    ]
  }
end

# Reusable file scanning logic
def scan_file(path, ext, rules)
  issues = []
  return issues unless File.exist?(path)

  File.readlines(path).each_with_index do |line, idx|
    rules[ext].each do |rule|
      if line.match?(rule[:pattern])
        issues << {
          line: idx + 1,
          message: rule[:message],
          suggestion: rule[:suggestion]
        }
      end
    end
  end

  issues
end
