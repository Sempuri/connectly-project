from singletons.config_manager import ConfigManager


# Create two instances of ConfigManager to test the singleton pattern
config1 = ConfigManager()
config2 = ConfigManager()

assert config1 is config2  # Ensure both instances refer to the same object (singleton pattern)
assert config1 is config2  # Both instances should be the same
config1.set_setting("DEFAULT_PAGE_SIZE", 50)
assert config2.get_setting("DEFAULT_PAGE_SIZE") == 50

print("Singleton test passed.")
