require "clowcard_cui"
require "thor"
require "docker-api"
require "tomoyo_linux_ruby"

module ClowCardCui
  class Cli < Thor
    desc "analysis", "analysis malware : [tagname] [malware_path] [execute time]"

    def analysis(name,malware_path,seconds)
      if File.exist?(malware_path) then
        #準備
        @malware_image = Docker::Image.create('fromImage' => 'ubuntu:16.04')
        @malware_image = @malware_image.insert_local('localPath' => malware_path, 'outputPath' => '/')
        @malware_image.tag('repo'=>name,'force'=>true)

        #TOMOYOLinuxの前処理
        @pol = TomoyoLinuxRuby::TomoyoPolicy.new("kernel")
        @pol.import()
        #todo:ここでTOMOYOLinuxのポリシーに実行するマルウェアのdomainを追加する.
        @base_domain_name = '<kernel> /sbin/init /usr/bin/dockerd /usr/bin/docker-containerd /usr/bin/docker-containerd-shim /usr/bin/docker-runc /proc/self/exe'
        @new_domain_name = @base_domain_name + ' /' + File.basename(malware_path)
        @pol.add_domain(@new_domain_name)
        @pol.set_profile(@new_domain_name,1)
        @pol.apply
        sleep(1)
        #実行
        @container = @malware_image.run('/'+File.basename(malware_path))
        sleep(seconds.to_i)

        #後処理
        if @container.info['State'] == 'running' then
          @container.kill
          @container.delete(:force => true)
        else
          @container.delete(:force => true)
        end
        @malware_image.remove(:force => true)

        #TomoyoLinuxの後処理
        @pol.import()
        r = @pol.get_domain_tree(@new_domain_name)
        r.each do |d|
          print d.to_s
        end
        @pol.remove_domains(@new_domain_name)
        @pol.apply

      else
        p "file is not exist"
      end
    end
  end
end
