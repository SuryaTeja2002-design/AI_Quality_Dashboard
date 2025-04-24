require 'sinatra'
require 'json'
require 'fileutils'

set :public_folder, File.dirname(__FILE__) + '/public'
set :views, File.dirname(__FILE__) + '/views'

post '/analyze' do
  if params[:file] && params[:file][:tempfile]
    file = params[:file][:tempfile]
    filename = params[:file][:filename]

    # Save uploaded file temporarily
    saved_path = "./uploads/#{filename}"
    FileUtils.mkdir_p('./uploads')
    File.open(saved_path, 'wb') { |f| f.write(file.read) }

    # Simple Analyzer: Flag some risky patterns
    results = []
    File.foreach(saved_path).with_index do |line, idx|
      results << { line: idx + 1, message: "Possible use of `eval`" } if line.include?("eval")
      results << { line: idx + 1, message: "Hardcoded password?" } if line.match?(/password\s*=\s*['"].+['"]/)
      results << { line: idx + 1, message: "Insecure use of system call" } if line.match?(/`.+`/)
    end

    erb :results, locals: { results: results, filename: filename }
  else
    redirect '/'
  end
end
