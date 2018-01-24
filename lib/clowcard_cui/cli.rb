require "clowcard_cui"
require "thor"
require "docker-api"
require "tomoyo_linux_ruby"
require 'fileutils'

module ClowCardCui
  class Cli < Thor
    desc "create_malware_image","create docker image with malware file"
    def create_malware_image(name,malware_path)
      @malware_image = Docker::Image.create('fromImage' => 'ubuntu:16.04')
      @malware_image = @malware_image.insert_local('localPath' => malware_path, 'outputPath' => '/')
      @malware_image.tag('repo'=>name,'force'=>true)
    end

    desc "tomoyo_learning", "change tomoyo learning mode"
    def tomoyo_learning(malware_path)
      @pol = TomoyoLinuxRuby::TomoyoPolicy.new("kernel")
      @pol.import
      #todo:ここでTOMOYOLinuxのポリシーに実行するマルウェアのdomainを追加する.
      @base_domain_name = '<kernel> /sbin/init /usr/bin/dockerd /usr/bin/docker-containerd /usr/bin/docker-containerd-shim /usr/bin/docker-runc /proc/self/exe /bin/bash'
      @new_domain_name = @base_domain_name + ' /' + File.basename(malware_path) + "\n"
      @pol.add_domain(@new_domain_name)
      @pol.set_profile(@new_domain_name,1)
      @pol.apply
    end

    desc "tomoyo_stop_learning","stop tomoyo_learning mode"
    def tomoyo_stop_learning(malware_path,output)
      @pol = TomoyoLinuxRuby::TomoyoPolicy.new("kernel")
      @pol.import
      @base_domain_name = '<kernel> /sbin/init /usr/bin/dockerd /usr/bin/docker-containerd /usr/bin/docker-containerd-shim /usr/bin/docker-runc /proc/self/exe /bin/bash'
      @new_domain_name = @base_domain_name + ' /' + File.basename(malware_path)
      r = @pol.get_domain_tree(@new_domain_name)
      File.open(output,"a") do |f|
        r.each do |d|
           f.puts d.to_s
        end
      end
      @pol.remove_domains(@new_domain_name)
      @pol.apply
    end

    desc "analysis", "analysis malware : [tagname] [malware_path] [execute time] [Output filepath]"
    def analysis(name,malware_path,seconds,output)
      if File.exist?(malware_path) then
        #準備
        print "Creating a malware image...\n"
        @malware_image = Docker::Image.create('fromImage' => 'ubuntu:16.04')
        @malware_image = @malware_image.insert_local('localPath' => malware_path, 'outputPath' => '/')
        @base_container = @malware_image.run("chmod 777 /"+File.basename(malware_path))
        @malware_image = @base_container.commit
        @malware_image.tag('repo'=>name,'force'=>true)
        #TOMOYOLinuxの前処理
        print "Adding new policy for the malware...\n"
        @pol = TomoyoLinuxRuby::TomoyoPolicy.new("kernel")
        @pol.import()
        #todo:ここでTOMOYOLinuxのポリシーに実行するマルウェアのdomainを追加する.
        @base_domain_name = '<kernel> /sbin/init /usr/bin/dockerd /usr/bin/docker-containerd /usr/bin/docker-containerd-shim /usr/bin/docker-runc /proc/self/exe'
        @new_domain_name = @base_domain_name + ' /' + File.basename(malware_path) + "\n"
        @pol.add_domain(@new_domain_name)
        @pol.set_profile(@new_domain_name,1)
        @pol.apply
        sleep(1)        #実行
        print "Executing malware container...\n"

        @container = @malware_image.run("/"+File.basename(malware_path))
        sleep(seconds.to_i)

        #後処理
        print "Removing malware ...\n"
        if @container.info['State'] == 'running' then
          @container.kill
          @container.delete(:force => true)
        else
          @container.delete(:force => true)
        end
        @malware_image.remove(:force => true)

        #TomoyoLinuxの後処理
        print "Analysing malware...\n"
        @pol_after = TomoyoLinuxRuby::TomoyoPolicy.new("kernel")
        @pol_after.import
        r = @pol_after.get_domain_tree(@new_domain_name)
        File.open(output,"a") do |f|
          r.each do |d|
             f.puts d.to_s
          end
        end
        @pol_after.remove_domains(@new_domain_name)
        @pol_after.apply

      else
        p "file is not exist"
      end
    end
  end
end
