from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from app.config import get_settings

_engine = None
_async_session_factory = None


def _ensure_initialized():
    """Lazily initialize the engine and session factory on first use."""
    global _engine, _async_session_factory
    if _async_session_factory is not None:
        return
    settings = get_settings()
    _engine = create_async_engine(settings.database_url, echo=False, pool_size=20, max_overflow=10)
    _async_session_factory = async_sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)


class _LazySessionFactory:
    """Wrapper that lazily initializes the real session factory on first call.

    Preserves the `async with async_session() as db:` calling convention.
    """

    def __call__(self):
        _ensure_initialized()
        return _async_session_factory()


async_session = _LazySessionFactory()


async def get_db() -> AsyncSession:
    _ensure_initialized()
    async with _async_session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
