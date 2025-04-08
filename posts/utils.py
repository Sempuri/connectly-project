from django.core.cache import cache
from django.conf import settings


def has_permission_to_manage_post(user, post):
    """
    Check if a user has permission to manage (edit/delete) a post
    Returns: Boolean
    """
    # Only admins and regular users (who are the authors) can manage posts
    if user.role == 'admin':
        return True
        
    # Post authors can manage their own posts (if they're not guests)
    if user == post.author and user.role != 'guest':
        return True
        
    return False

def can_view_post(user, post):
    """
    Check if a user can view a post based on privacy settings
    Returns: Boolean
    """
    # Public posts are visible to everyone
    if post.privacy == 'public':
        return True
        
    # Private posts are only visible to the author and admins
    if user == post.author or user.role == 'admin':
        return True
        
    return False

def get_cache_key(key_prefix, **kwargs):
    """
    Create a cache key with prefix and kwargs.
    Example: get_cache_key('feed', user_id=1, page=2) -> 'feed_user_id_1_page_2'
    """
    key_parts = [key_prefix]
    
    # Sort kwargs by key to ensure consistent ordering
    for k, v in sorted(kwargs.items()):
        key_parts.append(f"{k}_{v}")
        
    return "_".join(key_parts)

def delete_pattern_from_cache(pattern):
    """
    Delete all cache keys matching a pattern.
    This is a fallback for backends like LocMemCache that don't support delete_pattern.
    
    For Redis in production, this can be replaced with the native delete_pattern method.
    """
    if hasattr(cache, 'delete_pattern'):
        # Redis or other cache backend with native pattern support
        cache.delete_pattern(pattern)
    else:
        # For LocMemCache or other backends without pattern support
        # Find all keys (limited to known keys in current process)
        # This is a best-effort approach for development environments
        all_keys = cache._cache.keys()  # Access internal cache keys (works with LocMemCache)
        for key in all_keys:
            if pattern.replace('*', '') in key:
                cache.delete(key)