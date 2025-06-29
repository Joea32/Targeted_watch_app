"""Add total_checkins column to users

Revision ID: cd4c40b58ad8
Revises: 3c8f9f589a33
Create Date: 2025-06-08 02:10:45.492334

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'cd4c40b58ad8'
down_revision = '3c8f9f589a33'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('total_checkins', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('community_votes', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('proof_uploads', sa.Integer(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('proof_uploads')
        batch_op.drop_column('community_votes')
        batch_op.drop_column('total_checkins')

    # ### end Alembic commands ###
