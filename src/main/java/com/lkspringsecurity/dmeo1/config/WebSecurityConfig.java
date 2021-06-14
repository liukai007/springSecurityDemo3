package com.lkspringsecurity.dmeo1.config;

import com.lkspringsecurity.dmeo1.authcation.MyAuthenticationProcessingFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


    @Autowired
    public void config(AuthenticationManagerBuilder auth) throws Exception {
        // 在内存中配置用户，配置多个用户调用`and()`方法
        auth.inMemoryAuthentication()
                .passwordEncoder(passwordEncoder()) // 指定加密方式
                .withUser("admin").password(passwordEncoder().encode("123456")).roles("ADMIN")
                .and()
                .withUser("test").password(passwordEncoder().encode("123456")).roles("USER");
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // BCryptPasswordEncoder：Spring Security 提供的加密工具，可快速实现加密加盐
//        return new BCryptPasswordEncoder();
        return NoOpPasswordEncoder.getInstance();
    }

//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        //拦截器需要在此注册
//        http.addFilterBefore(new MyAuthenticationProcessingFilter(), AbstractPreAuthenticatedProcessingFilter.class);
//    }
}
