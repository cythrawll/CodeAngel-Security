Codeangel Security Framework for PHP
====================================

[![Build Status](https://travis-ci.org/cythrawll/CodeAngel-Security.png?branch=master)](https://travis-ci.org/cythrawll/CodeAngel-Security)

##Installation

With Composer:
You can install with [composer](http://getcomposer.org/), Simply add to your composer.json
```javascript
{
    "require": {
        "codeangel/security": "1.*"
    }
}       
```

Manually:
Just clone the repository, add the path to your include_path and then define a PSR-0 autolaoder
```
git clone https://github.com/cythrawll/CodeAngel-Security.git
```

```php
set_include_path('/path/to/codeangel/library/src'.PATH_SEPARATOR.get_include_path());

function codeagelAutoLoader($classname) {
    $className = ltrim($className, '\\');
    $filename = str_replace('\\', DIRECTORY_SEPARATOR, $classname).'.php';
    require $filename;
}

spl_autoload_register('codeangelAutoLoader');
```

##Requirements

* PHP >= 5.3
* `openssl` extension (required)
* `mcrypt` extension (recommended)
* `PDO` (recommended)
