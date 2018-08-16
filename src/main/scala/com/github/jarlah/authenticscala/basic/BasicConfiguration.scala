package com.github.jarlah.authenticscala.basic
import com.github.jarlah.authenticscala.Configuration
import com.typesafe.config.Config

final case class BasicConfiguration(realm: String) extends Configuration

object BasicConfiguration {
  def apply(config: Config): BasicConfiguration =
    BasicConfiguration(config.getString("authentic.basic.realm"))
}
