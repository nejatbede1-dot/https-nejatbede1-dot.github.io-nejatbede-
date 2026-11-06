-- Migration 0024: Social Media Base Tables

CREATE TABLE IF NOT EXISTS profiles (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL DEFAULT 'کاربر نجات بده',
    bio TEXT,
    avatar_url TEXT,
    website TEXT,
    is_private INTEGER NOT NULL DEFAULT 0 CHECK (is_private IN (0, 1)),
    follower_count INTEGER NOT NULL DEFAULT 0 CHECK (follower_count >= 0),
    following_count INTEGER NOT NULL DEFAULT 0 CHECK (following_count >= 0),
    post_count INTEGER NOT NULL DEFAULT 0 CHECK (post_count >= 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_profiles_display_name ON profiles(display_name);

INSERT INTO profiles (id, user_id, display_name)
SELECT lower(hex(randomblob(16))), u.id, 'کاربر نجات بده'
FROM users u
WHERE NOT EXISTS (SELECT 1 FROM profiles p WHERE p.user_id = u.id);

CREATE TABLE IF NOT EXISTS posts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content TEXT,
    post_type TEXT NOT NULL CHECK (post_type IN ('text', 'image', 'video', 'mixed')) DEFAULT 'text',
    visibility TEXT NOT NULL CHECK (visibility IN ('public', 'followers', 'private')) DEFAULT 'public',
    is_published INTEGER NOT NULL DEFAULT 0 CHECK (is_published IN (0, 1)),
    is_deleted INTEGER NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1)),
    like_count INTEGER NOT NULL DEFAULT 0 CHECK (like_count >= 0),
    comment_count INTEGER NOT NULL DEFAULT 0 CHECK (comment_count >= 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_posts_feed ON posts(is_published, is_deleted, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_posts_user_created ON posts(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_posts_visibility ON posts(visibility, is_published, is_deleted);

CREATE TABLE IF NOT EXISTS post_media (
    id TEXT PRIMARY KEY,
    post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    media_type TEXT NOT NULL CHECK (media_type IN ('image', 'video')) DEFAULT 'image',
    storage_key TEXT NOT NULL,
    thumbnail_key TEXT,
    file_size INTEGER CHECK (file_size IS NULL OR file_size >= 0),
    mime_type TEXT,
    duration_seconds INTEGER CHECK (duration_seconds IS NULL OR duration_seconds >= 0),
    width INTEGER CHECK (width IS NULL OR width >= 1),
    height INTEGER CHECK (height IS NULL OR height >= 1),
    sort_order INTEGER NOT NULL DEFAULT 0 CHECK (sort_order >= 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_post_media_post ON post_media(post_id);
CREATE INDEX IF NOT EXISTS idx_post_media_type ON post_media(media_type);
