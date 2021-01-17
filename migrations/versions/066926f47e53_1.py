"""1

Revision ID: 066926f47e53
Revises: 
Create Date: 2021-01-17 17:53:45.826746

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '066926f47e53'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('achievements',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=200), nullable=True),
    sa.Column('img', sa.String(length=200), nullable=True),
    sa.Column('achieved_at', sa.DateTime(), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('admin',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=200), nullable=True),
    sa.Column('password', sa.String(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('username')
    )
    op.create_table('site_info',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('key', sa.String(length=200), nullable=True),
    sa.Column('value', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('team',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=True),
    sa.Column('surname', sa.String(length=200), nullable=True),
    sa.Column('img', sa.String(length=200), nullable=True),
    sa.Column('role', sa.String(length=200), nullable=True),
    sa.Column('bio', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_team_role'), 'team', ['role'], unique=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_team_role'), table_name='team')
    op.drop_table('team')
    op.drop_table('site_info')
    op.drop_table('admin')
    op.drop_table('achievements')
    # ### end Alembic commands ###